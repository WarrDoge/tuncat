package engine

import (
	"testing"
)

func TestNewProfileDefaults(t *testing.T) {
	p := NewProfile()
	if p.Scheme != "https://" {
		t.Fatalf("Scheme = %q, want %q", p.Scheme, "https://")
	}
	if p.BasePath != "/" {
		t.Fatalf("BasePath = %q, want %q", p.BasePath, "/")
	}
	if p.Host != "" {
		t.Fatalf("Host = %q, want empty", p.Host)
	}
	if p.Initialized {
		t.Fatal("Initialized should be false")
	}
}

func TestNewProfileRoundTrip(t *testing.T) {
	p := NewProfile()
	p.Host = "vpn.example.com"
	p.Username = "user"
	p.Group = "Employees"
	p.Initialized = true
	p.ConfigHash = "abc123"
	p.DeviceID = "dev-01"

	if p.Host != "vpn.example.com" {
		t.Fatalf("Host = %q", p.Host)
	}
}

func TestNewAuthState(t *testing.T) {
	a := NewAuthState()
	if a.ReqHeaders == nil {
		t.Fatal("ReqHeaders should be initialized")
	}
	if len(a.ReqHeaders) != 0 {
		t.Fatalf("ReqHeaders should be empty, got %d entries", len(a.ReqHeaders))
	}
	if a.Conn != nil {
		t.Fatal("Conn should be nil")
	}
	if a.WebVPNCookie != "" {
		t.Fatal("WebVPNCookie should be empty")
	}
}

func TestNewContext(t *testing.T) {
	ctx := NewContext()
	if ctx.Cfg == nil {
		t.Fatal("Cfg should be initialized")
	}
	if ctx.LocalInterface == nil {
		t.Fatal("LocalInterface should be initialized")
	}
	if ctx.Logger == nil {
		t.Fatal("Logger should be initialized")
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
	if ctx.TLSCert != nil {
		t.Fatal("TLSCert should be nil (not configured yet)")
	}
	if ctx.RootCAs != nil {
		t.Fatal("RootCAs should be nil (not configured yet)")
	}
}

func TestContextRoundTrip(t *testing.T) {
	ctx := NewContext()
	ctx.Profile.Host = "vpn.test.local"
	ctx.Profile.Scheme = "http://"
	ctx.Profile.Username = "tester"

	if ctx.Profile.Host != "vpn.test.local" {
		t.Fatalf("Profile.Host = %q", ctx.Profile.Host)
	}
	if ctx.Profile.Username != "tester" {
		t.Fatalf("Profile.Username = %q", ctx.Profile.Username)
	}
}
