package auth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"runtime"
	"testing"

	"github.com/WarrDoge/tuncat/internal/engine"
	"github.com/WarrDoge/tuncat/internal/engine/protocol"
)

func TestDetectAnyConnectPlatform(t *testing.T) {
	platform := detectAnyConnectPlatform()
	if platform == "" {
		t.Fatal("detectAnyConnectPlatform returned empty string")
	}
	if len(platform) < len(runtime.GOOS) || platform[:len(runtime.GOOS)] != runtime.GOOS {
		t.Fatalf("platform %q does not start with GOOS %q", platform, runtime.GOOS)
	}
}

func TestResolveRequestPath(t *testing.T) {
	prof := engine.NewProfile()
	prof.BasePath = "/group"

	if got := resolveRequestPath(prof, ""); got != "/group" {
		t.Fatalf("resolveRequestPath(empty) = %q, want /group", got)
	}
	if got := resolveRequestPath(prof, "auth"); got != "/auth" {
		t.Fatalf("resolveRequestPath(relative) = %q, want /auth", got)
	}
	if got := resolveRequestPath(prof, "https://vpn.example.com/path?q=1"); got != "/path?q=1" {
		t.Fatalf("resolveRequestPath(absolute) = %q, want /path?q=1", got)
	}
}

func TestResolveRequestPathEdgeCases(t *testing.T) {
	t.Run("nil_profile", func(t *testing.T) {
		if got := resolveRequestPath(nil, ""); got != "/" {
			t.Fatalf("resolveRequestPath(nil, '') = %q, want /", got)
		}
	})

	t.Run("nil_profile_with_path", func(t *testing.T) {
		if got := resolveRequestPath(nil, "custom"); got != "/custom" {
			t.Fatalf("resolveRequestPath(nil, 'custom') = %q, want /custom", got)
		}
	})

	t.Run("absolute_url_no_path", func(t *testing.T) {
		prof := engine.NewProfile()
		// "https://" is parseable by url.Parse; the path is empty so it becomes "/".
		if got := resolveRequestPath(prof, "https://"); got != "/" {
			t.Fatalf("resolveRequestPath(bare-scheme) = %q, want /", got)
		}
	})

	t.Run("http_absolute_url", func(t *testing.T) {
		prof := engine.NewProfile()
		if got := resolveRequestPath(prof, "http://vpn.example.com/custom"); got != "/custom" {
			t.Fatalf("resolveRequestPath(http) = %q, want /custom", got)
		}
	})

	t.Run("empty_base_path_with_path", func(t *testing.T) {
		prof := &engine.Profile{}
		if got := resolveRequestPath(prof, "custom"); got != "/custom" {
			t.Fatalf("resolveRequestPath(empty-profile) = %q, want /custom", got)
		}
	})
}

func TestDTDHelpers(t *testing.T) {
	if msg := dtdErrorMessage(nil); msg != "" {
		t.Fatalf("dtdErrorMessage(nil) = %q, want empty", msg)
	}

	d1 := &protocol.DTD{}
	d1.Error.Value = "top-level error"
	if msg := dtdErrorMessage(d1); msg != "top-level error" {
		t.Fatalf("dtdErrorMessage(top-level) = %q", msg)
	}

	d2 := &protocol.DTD{}
	d2.Auth.Error.Value = "auth-level error"
	if msg := dtdErrorMessage(d2); msg != "auth-level error" {
		t.Fatalf("dtdErrorMessage(auth-level) = %q", msg)
	}
}

func TestClientCertRequested(t *testing.T) {
	if clientCertRequested(nil) {
		t.Fatal("clientCertRequested(nil) should be false")
	}
	if clientCertRequested(&protocol.DTD{}) {
		t.Fatal("clientCertRequested(empty dtd) should be false")
	}
	d := &protocol.DTD{ClientCertRequest: &struct{}{}}
	if !clientCertRequested(d) {
		t.Fatal("clientCertRequested should be true when challenge exists")
	}
}

func TestXMLEscape(t *testing.T) {
	if got := xmlEscape("<a&b>"); got != "&lt;a&amp;b&gt;" {
		t.Fatalf("xmlEscape = %q, want %q", got, "&lt;a&amp;b&gt;")
	}
}

func TestShouldRetryInitWithLinuxPlatform(t *testing.T) {
	notFound := &authHTTPStatusError{StatusCode: 404, Status: "404 Not Found"}
	forbidden := &authHTTPStatusError{StatusCode: 403, Status: "403 Forbidden"}

	tests := []struct {
		name     string
		goos     string
		platform string
		err      error
		want     bool
	}{
		{name: "windows 404 fallback", goos: "windows", platform: "windows-64", err: notFound, want: true},
		{name: "windows non-404", goos: "windows", platform: "windows-64", err: forbidden, want: false},
		{name: "linux no fallback", goos: "linux", platform: "windows-64", err: notFound, want: false},
		{name: "already linux platform", goos: "windows", platform: "linux-64", err: notFound, want: false},
		{name: "plain error", goos: "windows", platform: "windows-64", err: errors.New("other"), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldRetryInitWithLinuxPlatform(tc.goos, tc.platform, tc.err); got != tc.want {
				t.Fatalf("shouldRetryInitWithLinuxPlatform(%q, %q, %v) = %v, want %v", tc.goos, tc.platform, tc.err, got, tc.want)
			}
		})
	}
}

func TestRequestHostForURL(t *testing.T) {
	t.Run("nil_profile", func(t *testing.T) {
		if got := requestHostForURL(nil); got != "localhost" {
			t.Fatalf("requestHostForURL(nil) = %q, want localhost", got)
		}
	})

	t.Run("host_set", func(t *testing.T) {
		prof := engine.NewProfile()
		prof.Host = "vpn.example.com"
		if got := requestHostForURL(prof); got != "vpn.example.com" {
			t.Fatalf("requestHostForURL = %q, want vpn.example.com", got)
		}
	})

	t.Run("host_empty_falls_back_to_hostwithport", func(t *testing.T) {
		prof := engine.NewProfile()
		prof.HostWithPort = "vpn.example.com:443"
		if got := requestHostForURL(prof); got != "vpn.example.com:443" {
			t.Fatalf("requestHostForURL = %q, want vpn.example.com:443", got)
		}
	})

	t.Run("both_empty_returns_localhost", func(t *testing.T) {
		prof := engine.NewProfile()
		prof.Host = ""
		prof.HostWithPort = ""
		if got := requestHostForURL(prof); got != "localhost" {
			t.Fatalf("requestHostForURL = %q, want localhost", got)
		}
	})

	t.Run("host_with_whitespace", func(t *testing.T) {
		prof := engine.NewProfile()
		prof.Host = "  vpn.example.com  "
		if got := requestHostForURL(prof); got != "vpn.example.com" {
			t.Fatalf("requestHostForURL(with spaces) = %q, want vpn.example.com", got)
		}
	})
}

func TestSetAuthPlatform(t *testing.T) {
	t.Run("empty_platform_noop", func(t *testing.T) {
		authState := engine.NewAuthState()
		prof := engine.NewProfile()
		setAuthPlatform(authState, prof, "")
		if authState.ReqHeaders["X-AnyConnect-Platform"] != "" {
			t.Fatal("setAuthPlatform with empty platform should not set")
		}
	})

	t.Run("sets_both_state_and_profile", func(t *testing.T) {
		authState := engine.NewAuthState()
		prof := engine.NewProfile()
		setAuthPlatform(authState, prof, "linux-64")
		if authState.ReqHeaders["X-AnyConnect-Platform"] != "linux-64" {
			t.Fatalf("expected linux-64, got %q", authState.ReqHeaders["X-AnyConnect-Platform"])
		}
		if prof.DeviceID != "linux-64" {
			t.Fatalf("prof.DeviceID = %q, want linux-64", prof.DeviceID)
		}
	})

	t.Run("nil_auth_state_does_not_panic", func(t *testing.T) {
		prof := engine.NewProfile()
		setAuthPlatform(nil, prof, "linux-64")
		if prof.DeviceID != "linux-64" {
			t.Fatalf("prof.DeviceID = %q, want linux-64", prof.DeviceID)
		}
	})

	t.Run("nil_profile_does_not_panic", func(t *testing.T) {
		authState := engine.NewAuthState()
		setAuthPlatform(authState, nil, "linux-64")
		if authState.ReqHeaders["X-AnyConnect-Platform"] != "linux-64" {
			t.Fatalf("expected linux-64, got %q", authState.ReqHeaders["X-AnyConnect-Platform"])
		}
	})

	t.Run("nil_both_does_not_panic", func(t *testing.T) {
		setAuthPlatform(nil, nil, "linux-64") // should not panic
	})

	t.Run("trimmed_platform_set", func(t *testing.T) {
		authState := engine.NewAuthState()
		setAuthPlatform(authState, nil, "  windows-64  ")
		if authState.ReqHeaders["X-AnyConnect-Platform"] != "windows-64" {
			t.Fatalf("expected windows-64, got %q", authState.ReqHeaders["X-AnyConnect-Platform"])
		}
	})
}

func TestAuthHTTPStatusError(t *testing.T) {
	t.Run("nil_receiver", func(t *testing.T) {
		var e *authHTTPStatusError
		if got := e.Error(); got != "auth error" {
			t.Fatalf("nil error Error() = %q, want 'auth error'", got)
		}
	})

	t.Run("with_status_and_code", func(t *testing.T) {
		e := &authHTTPStatusError{StatusCode: 404, Status: "404 Not Found"}
		if got := e.Error(); got != "auth error 404 Not Found" {
			t.Fatalf("Error() = %q, want 'auth error 404 Not Found'", got)
		}
	})

	t.Run("with_code_only", func(t *testing.T) {
		e := &authHTTPStatusError{StatusCode: 500}
		if got := e.Error(); got != "auth error 500" {
			t.Fatalf("Error() = %q, want 'auth error 500'", got)
		}
	})

	t.Run("zero_value", func(t *testing.T) {
		e := &authHTTPStatusError{}
		if got := e.Error(); got != "auth error" {
			t.Fatalf("Error() = %q, want 'auth error'", got)
		}
	})
}

func TestCloseAuthConn(t *testing.T) {
	t.Run("nil_auth_state", func(t *testing.T) {
		closeAuthConn(nil) // should not panic
	})

	t.Run("nil_conn", func(t *testing.T) {
		closeAuthConn(&engine.AuthState{}) // should not panic
	})
}

func TestEnsureContext(t *testing.T) {
	t.Run("nil_context", func(t *testing.T) {
		if err := ensureContext(nil); err == nil {
			t.Fatal("ensureContext(nil) expected error")
		}
	})

	t.Run("nil_context_returns_error_message", func(t *testing.T) {
		err := ensureContext(nil)
		if err.Error() != "vpn context is nil" {
			t.Fatalf("ensureContext(nil) = %q, want 'vpn context is nil'", err.Error())
		}
	})

	t.Run("empty_context_sets_defaults", func(t *testing.T) {
		ctx := &engine.Context{}
		if err := ensureContext(ctx); err != nil {
			t.Fatalf("ensureContext(empty) error: %v", err)
		}
		if ctx.Cfg == nil {
			t.Fatal("ensureContext should set Cfg")
		}
		if ctx.Logger == nil {
			t.Fatal("ensureContext should set Logger")
		}
		if ctx.Profile == nil {
			t.Fatal("ensureContext should set Profile")
		}
		if ctx.Session == nil {
			t.Fatal("ensureContext should set Session")
		}
		if ctx.Auth == nil {
			t.Fatal("ensureContext should set Auth")
		}
	})

	t.Run("preserves_existing_values", func(t *testing.T) {
		ctx := &engine.Context{}
		_ = ensureContext(ctx)
		origCfg := ctx.Cfg
		origProfile := ctx.Profile
		_ = ensureContext(ctx)
		if ctx.Cfg != origCfg {
			t.Fatal("ensureContext should preserve existing Cfg")
		}
		if ctx.Profile != origProfile {
			t.Fatal("ensureContext should preserve existing Profile")
		}
	})

	t.Run("nil_profile_gives_default_scheme_and_basepath", func(t *testing.T) {
		ctx := &engine.Context{}
		_ = ensureContext(ctx)
		if ctx.Profile.Scheme != "https://" {
			t.Fatalf("Profile.Scheme = %q, want https://", ctx.Profile.Scheme)
		}
		if ctx.Profile.BasePath != "/" {
			t.Fatalf("Profile.BasePath = %q, want /", ctx.Profile.BasePath)
		}
	})
}

func TestDefaultRequestHeaders(t *testing.T) {
	headers := defaultRequestHeaders()
	if headers == nil {
		t.Fatal("defaultRequestHeaders returned nil")
	}
	requiredKeys := []string{"X-Transcend-Version", "X-Aggregate-Auth", "X-Support-HTTP-Auth", "X-AnyConnect-Platform", "Accept", "Accept-Encoding"}
	for _, key := range requiredKeys {
		if v, ok := headers[key]; !ok || v == "" {
			t.Fatalf("defaultRequestHeaders missing or empty %q", key)
		}
	}
}

func TestSetTLSCredentials(t *testing.T) {
	t.Run("nil_context_noop", func(t *testing.T) {
		cert := tls.Certificate{}
		SetTLSCredentials(nil, cert, nil) // should not panic
	})

	t.Run("sets_cert_and_rootcas", func(t *testing.T) {
		ctx := &engine.Context{}
		cert := tls.Certificate{}
		pool := x509.NewCertPool()
		SetTLSCredentials(ctx, cert, pool)
		if ctx.TLSCert == nil {
			t.Fatal("TLSCert should be set")
		}
		if ctx.RootCAs != pool {
			t.Fatal("RootCAs should be set")
		}
	})
}

func TestClearTLSCredentials(t *testing.T) {
	t.Run("nil_context_noop", func(t *testing.T) {
		ClearTLSCredentials(nil) // should not panic
	})

	t.Run("clears_cert_and_rootcas", func(t *testing.T) {
		ctx := &engine.Context{}
		_ = ensureContext(ctx)
		ctx.TLSCert = &tls.Certificate{}
		ctx.RootCAs = x509.NewCertPool()
		ClearTLSCredentials(ctx)
		if ctx.TLSCert != nil {
			t.Fatal("TLSCert should be nil after clear")
		}
		if ctx.RootCAs != nil {
			t.Fatal("RootCAs should be nil after clear")
		}
	})
}

func TestApplyTLSOptions(t *testing.T) {
	t.Run("nil_context_returns_error", func(t *testing.T) {
		config := &tls.Config{}
		if err := applyTLSOptions(config, nil); err == nil {
			t.Fatal("applyTLSOptions with nil context expected error")
		}
	})

	t.Run("no_cert_no_pin_no_op", func(t *testing.T) {
		ctx := &engine.Context{}
		_ = ensureContext(ctx)
		config := &tls.Config{}
		if err := applyTLSOptions(config, ctx); err != nil {
			t.Fatalf("applyTLSOptions error: %v", err)
		}
		// Should still have InsecureSkipVerify as false (unchanged)
		if config.InsecureSkipVerify {
			t.Fatal("InsecureSkipVerify should be false when no pin is set")
		}
	})

	t.Run("cert_sets_getclientcertificate_callback", func(t *testing.T) {
		ctx := &engine.Context{}
		_ = ensureContext(ctx)
		cert := tls.Certificate{}
		SetTLSCredentials(ctx, cert, nil)
		config := &tls.Config{}
		if err := applyTLSOptions(config, ctx); err != nil {
			t.Fatalf("applyTLSOptions error: %v", err)
		}
		if config.GetClientCertificate == nil {
			t.Fatal("GetClientCertificate should be set when TLSCert is present")
		}
	})

	t.Run("pin_sets_verify_connection", func(t *testing.T) {
		ctx := &engine.Context{}
		_ = ensureContext(ctx)
		ctx.Cfg.ServerCertPin = "sha256:abcd1234"
		config := &tls.Config{}
		if err := applyTLSOptions(config, ctx); err != nil {
			t.Fatalf("applyTLSOptions error: %v", err)
		}
		if !config.InsecureSkipVerify {
			t.Fatal("InsecureSkipVerify should be true when pin is set")
		}
		if config.VerifyConnection == nil {
			t.Fatal("VerifyConnection should be set when pin is present")
		}
	})
}
