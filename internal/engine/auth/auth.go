package auth

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/WarrDoge/tuncat/internal/engine"
	engineconfig "github.com/WarrDoge/tuncat/internal/engine/config"
	"github.com/WarrDoge/tuncat/internal/engine/netutil"
	"github.com/WarrDoge/tuncat/internal/engine/protocol"
	enginesession "github.com/WarrDoge/tuncat/internal/engine/session"
)

const (
	tplInit = iota
	tplAuthReply
)

func ensureContext(ctx *engine.Context) error {
	if ctx == nil {
		return errors.New("vpn context is nil")
	}
	if ctx.Cfg == nil {
		ctx.Cfg = engineconfig.NewClientConfig()
	}
	if ctx.Logger == nil {
		ctx.Logger = engineconfig.NewLogger(ctx.Cfg)
	}
	engineconfig.SetDefaultLogger(ctx.Logger)
	if ctx.Profile == nil {
		ctx.Profile = engine.NewProfile()
	}
	if ctx.Session == nil {
		ctx.Session = &enginesession.Session{}
	}
	if ctx.Auth == nil {
		ctx.Auth = engine.NewAuthState()
	}
	if len(ctx.Auth.ReqHeaders) == 0 {
		ctx.Auth.ReqHeaders = defaultRequestHeaders()
	}
	if ctx.Profile.Scheme == "" {
		ctx.Profile.Scheme = "https://"
	}
	if ctx.Profile.BasePath == "" {
		ctx.Profile.BasePath = "/"
	}
	if ctx.Profile.DeviceID == "" {
		platform := ctx.Auth.ReqHeaders["X-AnyConnect-Platform"]
		if platform == "" {
			platform = detectAnyConnectPlatform()
		}
		ctx.Profile.DeviceID = platform
	}
	return nil
}

func defaultRequestHeaders() map[string]string {
	platform := detectAnyConnectPlatform()
	return map[string]string{
		"X-Transcend-Version":   "1",
		"X-Aggregate-Auth":      "1",
		"X-Support-HTTP-Auth":   "true",
		"X-AnyConnect-Platform": platform,
		"Accept":                "*/*",
		"Accept-Encoding":       "identity",
	}
}

func InitAuth(ctx *engine.Context) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	authState := ctx.Auth
	prof := ctx.Profile
	cfg := ctx.Cfg

	authState.WebVPNCookie = ""
	// TLS transport is established once and reused by auth POST exchanges.
	config := tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	if err := applyTLSOptions(&config, ctx); err != nil {
		return err
	}
	openConn := func() error {
		var err error
		authState.Conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 6 * time.Second}, "tcp4", prof.HostWithPort, &config)
		if err != nil {
			return err
		}
		authState.BufR = bufio.NewReader(authState.Conn)
		return nil
	}
	if err := openConn(); err != nil {
		return err
	}

	var err error
	dtd := new(protocol.DTD)

	prof.AppVersion = cfg.AgentVersion
	prof.GroupAccess = fmt.Sprintf("%s%s%s", prof.Scheme, requestHostForURL(prof), resolveRequestPath(prof, prof.BasePath))

	err = tplPost(ctx, tplInit, "", dtd)
	if err != nil && shouldRetryInitWithLinuxPlatform(runtime.GOOS, authState.ReqHeaders["X-AnyConnect-Platform"], err) {
		engineconfig.Info("auth init returned 404 for windows-64; retrying with linux-64 compatibility profile")
		setAuthPlatform(authState, prof, "linux-64")
		if err := openConn(); err != nil {
			return err
		}
		dtd = new(protocol.DTD)
		err = tplPost(ctx, tplInit, "", dtd)
	}
	if err != nil {
		return err
	}
	if msg := dtdErrorMessage(dtd); msg != "" {
		return errors.New(msg)
	}
	if clientCertRequested(dtd) {
		// Some gateways request client-cert capability first and then expect
		// a fresh init request on a new TLS connection.
		if authState.Conn != nil {
			authState.Conn.Close()
		}
		if err := openConn(); err != nil {
			return err
		}
		dtd = new(protocol.DTD)
		err = tplPost(ctx, tplInit, "", dtd)
		if err != nil {
			return err
		}
		if msg := dtdErrorMessage(dtd); msg != "" {
			return errors.New(msg)
		}
		if clientCertRequested(dtd) {
			return errors.New("gateway repeatedly requested client certificate")
		}
	}

	prof.AuthPath = dtd.Auth.Form.Action
	if prof.AuthPath == "" {
		prof.AuthPath = resolveRequestPath(prof, prof.BasePath)
	}
	prof.TunnelGroup = dtd.Opaque.TunnelGroup
	prof.AuthMethod = dtd.Opaque.AuthMethod
	prof.GroupAlias = dtd.Opaque.GroupAlias
	prof.ConfigHash = dtd.Opaque.ConfigHash

	gps := len(dtd.Auth.Form.Groups)
	if gps != 0 && !netutil.InArray(dtd.Auth.Form.Groups, prof.Group) {
		return fmt.Errorf("available user groups are: %s", strings.Join(dtd.Auth.Form.Groups, " "))
	}

	return nil
}

func PasswordAuth(ctx *engine.Context) error {
	if err := ensureContext(ctx); err != nil {
		return err
	}
	prof := ctx.Profile
	authState := ctx.Auth
	sess := ctx.Session

	dtd := new(protocol.DTD)
	err := tplPost(ctx, tplAuthReply, prof.AuthPath, dtd)
	if err != nil {
		return err
	}
	if msg := dtdErrorMessage(dtd); msg != "" {
		return errors.New(msg)
	}
	if dtd.Type == "auth-request" && dtd.Auth.Error.Value == "" {
		// Handle two-step auth flow where server asks for credentials twice.
		dtd = new(protocol.DTD)
		err = tplPost(ctx, tplAuthReply, prof.AuthPath, dtd)
		if err != nil {
			return err
		}
		if msg := dtdErrorMessage(dtd); msg != "" {
			return errors.New(msg)
		}
	}
	if dtd.Type == "auth-request" {
		if dtd.Auth.Error.Value != "" {
			return fmt.Errorf(dtd.Auth.Error.Value, dtd.Auth.Error.Param1)
		}
		return errors.New(dtd.Auth.Message)
	}

	sess.SessionToken = dtd.SessionToken
	// Some servers return auth success via webvpn cookie instead of XML token.
	if authState.WebVPNCookie != "" {
		sess.SessionToken = authState.WebVPNCookie
	}
	if strings.TrimSpace(sess.SessionToken) == "" {
		return errors.New("authentication succeeded without a session token")
	}
	engineconfig.Debug("SessionToken: [present]")
	return nil
}

var (
	parsedTemplateInit = template.Must(template.New("init").Funcs(template.FuncMap{
		"xmlEscape": xmlEscape,
	}).Parse(templateInit))
	parsedTemplateAuthReply = template.Must(template.New("auth_reply").Funcs(template.FuncMap{
		"xmlEscape": xmlEscape,
	}).Parse(templateAuthReply))
)

func tplPost(ctx *engine.Context, typ int, path string, dtd *protocol.DTD) error {
	prof := ctx.Profile
	authState := ctx.Auth
	cfg := ctx.Cfg

	tplBuffer := new(bytes.Buffer)
	var err error
	if typ == tplInit {
		err = parsedTemplateInit.Execute(tplBuffer, prof)
	} else {
		err = parsedTemplateAuthReply.Execute(tplBuffer, prof)
	}
	if err != nil {
		return fmt.Errorf("template execute: %w", err)
	}
	if cfg.LogLevel == "Debug" {
		post := tplBuffer.String()
		if typ == tplAuthReply {
			post = netutil.RemoveBetween(post, "<auth>", "</auth>")
		}
		engineconfig.Debug(post)
	}
	// Auth path may be absolute URL, relative path, or empty fallback.
	requestPath := resolveRequestPath(prof, path)
	url := fmt.Sprintf("%s%s%s", prof.Scheme, requestHostForURL(prof), requestPath)
	if prof.SecretKey != "" {
		if strings.Contains(url, "?") {
			url += "&" + prof.SecretKey
		} else {
			url += "?" + prof.SecretKey
		}
	}
	engineconfig.Debug("auth POST", url)
	req, _ := http.NewRequest("POST", url, tplBuffer)

	netutil.SetCommonHeader(req, cfg.AgentName, cfg.AgentVersion, cfg.CiscoCompat)
	if cfg.CiscoCompat {
		req.Header.Set("User-Agent", fmt.Sprintf("Open AnyConnect VPN Agent %s", prof.AppVersion))
	}
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	for k, v := range authState.ReqHeaders {
		req.Header[k] = []string{v}
	}
	if authState.Conn == nil || authState.BufR == nil {
		return errors.New("auth transport is not initialized")
	}

	err = req.Write(authState.Conn)
	if err != nil {
		closeAuthConn(authState)
		return err
	}

	var resp *http.Response
	resp, err = http.ReadResponse(authState.BufR, req)
	if err != nil {
		closeAuthConn(authState)
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		closeAuthConn(authState)
		return err
	}
	if cfg.LogLevel == "Debug" {
		engineconfig.Debug(string(body))
	}

	if resp.StatusCode == http.StatusOK {
		err = xml.Unmarshal(body, dtd)
		if dtd.Type == "complete" && dtd.SessionToken == "" {
			cookies := resp.Cookies()
			if len(cookies) != 0 {
				for _, c := range cookies {
					if c.Name == "webvpn" {
						authState.WebVPNCookie = c.Value
						break
					}
				}
			}
		}
		// nil
		return err
	}
	closeAuthConn(authState)
	return &authHTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
}

type authHTTPStatusError struct {
	StatusCode int
	Status     string
}

func (e *authHTTPStatusError) Error() string {
	if e == nil {
		return "auth error"
	}
	if strings.TrimSpace(e.Status) != "" {
		return fmt.Sprintf("auth error %s", e.Status)
	}
	if e.StatusCode != 0 {
		return fmt.Sprintf("auth error %d", e.StatusCode)
	}
	return "auth error"
}

func closeAuthConn(authState *engine.AuthState) {
	if authState != nil && authState.Conn != nil {
		authState.Conn.Close()
		authState.Conn = nil
		authState.BufR = nil
	}
}

func resolveRequestPath(prof *engine.Profile, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		if prof != nil {
			path = strings.TrimSpace(prof.BasePath)
		}
	}
	if path == "" {
		return "/"
	}
	if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "http://") {
		u, err := url.Parse(path)
		if err == nil {
			path = u.EscapedPath()
			if path == "" {
				path = "/"
			}
			if u.RawQuery != "" {
				path += "?" + u.RawQuery
			}
			return path
		}
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func requestHostForURL(prof *engine.Profile) string {
	if prof == nil {
		return "localhost"
	}
	host := strings.TrimSpace(prof.Host)
	if host != "" {
		return host
	}
	host = strings.TrimSpace(prof.HostWithPort)
	if host != "" {
		return host
	}
	return "localhost"
}

func detectAnyConnectPlatform() string {
	platform := runtime.GOOS + "-" + runtime.GOARCH
	switch runtime.GOARCH {
	case "amd64", "arm64", "ppc64", "ppc64le", "mips64", "mips64le":
		platform = runtime.GOOS + "-64"
	}
	return platform
}

func shouldRetryInitWithLinuxPlatform(goos, platform string, err error) bool {
	if !strings.EqualFold(strings.TrimSpace(goos), "windows") {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(platform), "windows-64") {
		return false
	}
	var statusErr *authHTTPStatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	return statusErr.StatusCode == http.StatusNotFound
}

func setAuthPlatform(authState *engine.AuthState, prof *engine.Profile, platform string) {
	platform = strings.TrimSpace(platform)
	if platform == "" {
		return
	}
	if authState != nil {
		if authState.ReqHeaders == nil {
			authState.ReqHeaders = defaultRequestHeaders()
		}
		authState.ReqHeaders["X-AnyConnect-Platform"] = platform
	}
	if prof != nil {
		prof.DeviceID = platform
	}
}

func dtdErrorMessage(dtd *protocol.DTD) string {
	if dtd == nil {
		return ""
	}
	if msg := strings.TrimSpace(dtd.Error.Value); msg != "" {
		return msg
	}
	if msg := strings.TrimSpace(dtd.Auth.Error.Value); msg != "" {
		return msg
	}
	return ""
}

func clientCertRequested(dtd *protocol.DTD) bool {
	return dtd != nil && dtd.ClientCertRequest != nil
}

func xmlEscape(value string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}

var templateInit = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
    <version who="vpn">{{.AppVersion}}</version>
    <device-id>{{.DeviceID}}</device-id>
    <capabilities>
        <auth-method>single-sign-on-v2</auth-method>
        <auth-method>single-sign-on-external-browser</auth-method>
    </capabilities>
    <group-access>{{xmlEscape .GroupAccess}}</group-access>
</config-auth>`

// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03#section-2.1.2.2
var templateAuthReply = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
    <version who="vpn">{{.AppVersion}}</version>
    <device-id>{{.DeviceID}}</device-id>
    <capabilities>
        <auth-method>single-sign-on-v2</auth-method>
        <auth-method>single-sign-on-external-browser</auth-method>
    </capabilities>
    <opaque is-for="sg">
        {{- if .TunnelGroup }}
        <tunnel-group>{{xmlEscape .TunnelGroup}}</tunnel-group>
        {{- end }}
        {{- if .AuthMethod }}
        <auth-method>{{xmlEscape .AuthMethod}}</auth-method>
        {{- end }}
        {{- if .GroupAlias }}
        <group-alias>{{xmlEscape .GroupAlias}}</group-alias>
        {{- end }}
        {{- if .ConfigHash }}
        <config-hash>{{xmlEscape .ConfigHash}}</config-hash>
        {{- end }}
    </opaque>
    <auth>
        <username>{{xmlEscape .Username}}</username>
        <password>{{xmlEscape .Password}}</password>
    </auth>
</config-auth>`
