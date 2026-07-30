package auth

import (
	"crypto/tls"
	"errors"
	"testing"

	"github.com/WarrDoge/tuncat/internal/engine"
	engineconfig "github.com/WarrDoge/tuncat/internal/engine/config"
)

func TestDefaultRequestHeaders(t *testing.T) {
	headers := defaultRequestHeaders()
	if headers == nil {
		t.Fatal("defaultRequestHeaders returned nil")
	}
	if v := headers["X-Transcend-Version"]; v != "1" {
		t.Fatalf("X-Transcend-Version = %q, want 1", v)
	}
	if v := headers["X-Aggregate-Auth"]; v != "1" {
		t.Fatalf("X-Aggregate-Auth = %q, want 1", v)
	}
	if v := headers["X-Support-HTTP-Auth"]; v != "true" {
		t.Fatalf("X-Support-HTTP-Auth = %q, want true", v)
	}
	if v := headers["Accept"]; v != "*/*" {
		t.Fatalf("Accept = %q, want */*", v)
	}
	if v := headers["Accept-Encoding"]; v != "identity" {
		t.Fatalf("Accept-Encoding = %q, want identity", v)
	}
	if v := headers["X-AnyConnect-Platform"]; v == "" {
		t.Fatal("X-AnyConnect-Platform should not be empty")
	}
}

func TestSetAuthPlatformEmptyDoesNothing(t *testing.T) {
	authState := engine.NewAuthState()
	prof := engine.NewProfile()

	setAuthPlatform(authState, prof, "")
	if authState.ReqHeaders["X-AnyConnect-Platform"] != "" {
		t.Fatal("setAuthPlatform with empty string should not modify headers")
	}
}

func TestSetAuthPlatformSetsBoth(t *testing.T) {
	authState := engine.NewAuthState()
	prof := engine.NewProfile()

	setAuthPlatform(authState, prof, "linux-64")
	if authState.ReqHeaders["X-AnyConnect-Platform"] != "linux-64" {
		t.Fatalf("platform header = %q, want linux-64", authState.ReqHeaders["X-AnyConnect-Platform"])
	}
	if prof.DeviceID != "linux-64" {
		t.Fatalf("DeviceID = %q, want linux-64", prof.DeviceID)
	}
}

func TestSetAuthPlatformWithNilAuthState(t *testing.T) {
	prof := engine.NewProfile()
	// Should not panic.
	setAuthPlatform(nil, prof, "linux-64")
}

func TestSetAuthPlatformWithNilProf(t *testing.T) {
	authState := engine.NewAuthState()
	// Should not panic.
	setAuthPlatform(authState, nil, "linux-64")
	if authState.ReqHeaders["X-AnyConnect-Platform"] != "linux-64" {
		t.Fatalf("platform header = %q, want linux-64", authState.ReqHeaders["X-AnyConnect-Platform"])
	}
}

func TestRequestHostForURLWithHost(t *testing.T) {
	prof := engine.NewProfile()
	prof.Host = "vpn.example.com"

	if host := requestHostForURL(prof); host != "vpn.example.com" {
		t.Fatalf("requestHostForURL = %q, want vpn.example.com", host)
	}
}

func TestRequestHostForURLFallsBackToHostWithPort(t *testing.T) {
	prof := engine.NewProfile()
	prof.HostWithPort = "10.0.0.1:443"

	if host := requestHostForURL(prof); host != "10.0.0.1:443" {
		t.Fatalf("requestHostForURL = %q, want 10.0.0.1:443", host)
	}
}

func TestRequestHostForURLNilProfile(t *testing.T) {
	if host := requestHostForURL(nil); host != "localhost" {
		t.Fatalf("requestHostForURL(nil) = %q, want localhost", host)
	}
}

func TestRequestHostForURLEmptyHosts(t *testing.T) {
	prof := engine.NewProfile()
	if host := requestHostForURL(prof); host != "localhost" {
		t.Fatalf("requestHostForURL = %q, want localhost", host)
	}
}

func TestRequestHostForURLTrimsSpaces(t *testing.T) {
	prof := engine.NewProfile()
	prof.Host = "  vpn.example.com  "

	if host := requestHostForURL(prof); host != "vpn.example.com" {
		t.Fatalf("requestHostForURL = %q, want vpn.example.com", host)
	}
}

func TestResolveRequestPathEmptyProfileFallsBack(t *testing.T) {
	if got := resolveRequestPath(nil, ""); got != "/" {
		t.Fatalf("resolveRequestPath(nil, \"\") = %q, want /", got)
	}
}

func TestEnsureContextInitializesDefaults(t *testing.T) {
	ctx := &engine.Context{}

	if err := ensureContext(ctx); err != nil {
		t.Fatalf("ensureContext error: %v", err)
	}
	if ctx.Cfg == nil {
		t.Fatal("Cfg should be initialized")
	}
	if ctx.Profile == nil {
		t.Fatal("Profile should be initialized")
	}
	if ctx.Session == nil {
		t.Fatal("Session should be initialized")
	}
	if ctx.Auth == nil {
		t.Fatal("Auth should be initialized")
	}
	if ctx.Profile.Scheme != "https://" {
		t.Fatalf("Profile.Scheme = %q, want https://", ctx.Profile.Scheme)
	}
	if ctx.Profile.BasePath != "/" {
		t.Fatalf("Profile.BasePath = %q, want /", ctx.Profile.BasePath)
	}
}

func TestEnsureContextNilReturnsError(t *testing.T) {
	if err := ensureContext(nil); err == nil {
		t.Fatal("expected error for nil context")
	}
}

func TestAuthHTTPStatusError(t *testing.T) {
	tests := []struct {
		name string
		err  *authHTTPStatusError
		want string
	}{
		{name: "nil", err: nil, want: "auth error"},
		{name: "with status", err: &authHTTPStatusError{StatusCode: 404, Status: "404 Not Found"}, want: "auth error 404 Not Found"},
		{name: "code only", err: &authHTTPStatusError{StatusCode: 500}, want: "auth error 500"},
		{name: "empty", err: &authHTTPStatusError{}, want: "auth error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyTLSOptionsEmptyPin(t *testing.T) {
	cfg := engineconfig.NewClientConfig()
	cfg.ServerCertPin = ""
	ctx := &engine.Context{Cfg: cfg}

	tlsCfg := &tls.Config{}
	if err := applyTLSOptions(tlsCfg, ctx); err != nil {
		t.Fatalf("applyTLSOptions with empty pin: %v", err)
	}
}

func TestCloseAuthConnNil(t *testing.T) {
	// Should not panic.
	closeAuthConn(nil)
}

func TestCloseAuthConnNilConn(t *testing.T) {
	authState := engine.NewAuthState()
	authState.Conn = nil
	// Should not panic.
	closeAuthConn(authState)
}

func TestShouldRetryInitWithLinuxPlatformEdgeCases(t *testing.T) {
	if got := shouldRetryInitWithLinuxPlatform("windows", "windows-64", errors.New("plain error")); got {
		t.Fatal("expected false for plain error")
	}
}

func TestClientCertRequestedNil(t *testing.T) {
	if clientCertRequested(nil) {
		t.Fatal("expected false for nil DTD")
	}
}

func TestDTDErrorMessageNil(t *testing.T) {
	if msg := dtdErrorMessage(nil); msg != "" {
		t.Fatalf("dtdErrorMessage(nil) = %q, want empty", msg)
	}
}

func TestXMLEscapeEmpty(t *testing.T) {
	if got := xmlEscape(""); got != "" {
		t.Fatalf("xmlEscape(\"\") = %q, want empty", got)
	}
}
