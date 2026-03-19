package tunnel

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/WarrDoge/tuncat/internal/engine"
	engineconfig "github.com/WarrDoge/tuncat/internal/engine/config"
	"github.com/WarrDoge/tuncat/internal/engine/netutil"
	"github.com/WarrDoge/tuncat/internal/engine/network"
)

func initTunnel(ctx *engine.Context) map[string]string {
	mtu := ctx.Cfg.BaseMTU
	if mtu <= 0 {
		mtu = 1200
	}
	reqHeaders := map[string]string{
		"X-CSTP-VPNAddress-Type": "IPv4",
		"X-CSTP-MTU":             strconv.Itoa(mtu),
		"X-CSTP-Base-MTU":        strconv.Itoa(mtu),
	}

	// Session token is always sent as webvpn cookie for CSTP CONNECT.
	reqHeaders["Cookie"] = "webvpn=" + ctx.Session.SessionToken
	reqHeaders["X-CSTP-Local-VPNAddress-IP4"] = ctx.LocalInterface.Ip4

	// Legacy DTLS bootstrap: pre-master secret is provided by header.
	ctx.Session.PreMasterSecret, _ = netutil.MakeMasterSecret()
	reqHeaders["X-DTLS-Master-Secret"] = hex.EncodeToString(ctx.Session.PreMasterSecret)

	// Keep suite list aligned with OpenConnect/ocserv interop behavior.
	reqHeaders["X-DTLS12-CipherSuite"] = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256"

	return reqHeaders
}

// SetupTunnel initiates an HTTP CONNECT command to establish a VPN
func SetupTunnel(ctx *engine.Context) error {
	if ctx == nil {
		return errors.New("vpn context is nil")
	}
	if ctx.Cfg == nil || ctx.Profile == nil || ctx.Session == nil || ctx.Auth == nil || ctx.LocalInterface == nil {
		return errors.New("vpn context is incomplete")
	}
	if ctx.Auth.Conn == nil || ctx.Auth.BufR == nil {
		return errors.New("auth transport is not initialized")
	}

	prof := ctx.Profile
	cfg := ctx.Cfg
	authState := ctx.Auth
	reqHeaders := initTunnel(ctx)

	// Write CONNECT request manually so we fully control non-standard headers.
	req, _ := http.NewRequest("CONNECT", prof.Scheme+prof.HostWithPort+"/CSCOSSLC/tunnel", nil)
	netutil.SetCommonHeader(req, cfg.AgentName, cfg.AgentVersion, cfg.CiscoCompat)
	for k, v := range reqHeaders {
		req.Header[k] = []string{v}
	}

	err := req.Write(authState.Conn)
	if err != nil {
		authState.Conn.Close()
		return err
	}
	var resp *http.Response
	// resp.Body is closed by tlsChannel.
	resp, err = http.ReadResponse(authState.BufR, req)
	if err != nil {
		authState.Conn.Close()
		return err
	}

	if resp.StatusCode != http.StatusOK {
		authState.Conn.Close()
		return fmt.Errorf("tunnel negotiation failed %s", resp.Status)
	}
	if cfg.LogLevel == "Debug" {
		headers := make([]byte, 0)
		buf := bytes.NewBuffer(headers)
		// Header keys are canonicalized by net/http.
		_ = resp.Header.Write(buf)
		engineconfig.Debug(buf.String())
	}

	cSess := ctx.Session.NewConnSession(&resp.Header, ctx.LocalInterface.Ip4, cfg.NoDTLS)
	cSess.ServerAddress = strings.Split(authState.Conn.RemoteAddr().String(), ":")[0]
	cSess.Hostname = prof.Host
	cSess.TLSCipherSuite = tls.CipherSuiteName(authState.Conn.ConnectionState().CipherSuite)

	err = setupTun(ctx, cSess)
	if err != nil {
		authState.Conn.Close()
		cSess.Close()
		return err
	}

	if !cfg.NoDTLS && cSess.DTLSPort != "" {
		// DTLS handshake depends only on negotiated CSTP session parameters and
		// can overlap with local route and DNS setup.
		go dtlsChannel(cSess, ctx.Session.PreMasterSecret)
	}

	// Route and DNS setup stays synchronous relative to the data plane startup.
	err = network.SetRoutes(ctx, cSess)
	if err != nil {
		authState.Conn.Close()
		cSess.Close()
		return err
	}
	engineconfig.Info("tls channel negotiation succeeded")

	go tlsChannel(authState.Conn, authState.BufR, cSess, resp)

	cSess.DPDTimer()
	cSess.ReadDeadTimer()

	return err
}
