package auth

import (
	"errors"
	"runtime"
	"testing"

	vpncore "tuncat/internal/vpncore"
	"tuncat/internal/vpncore/proto"
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
	prof := vpncore.NewProfile()
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

func TestDTDHelpers(t *testing.T) {
	if msg := dtdErrorMessage(nil); msg != "" {
		t.Fatalf("dtdErrorMessage(nil) = %q, want empty", msg)
	}

	d1 := &proto.DTD{}
	d1.Error.Value = "top-level error"
	if msg := dtdErrorMessage(d1); msg != "top-level error" {
		t.Fatalf("dtdErrorMessage(top-level) = %q", msg)
	}

	d2 := &proto.DTD{}
	d2.Auth.Error.Value = "auth-level error"
	if msg := dtdErrorMessage(d2); msg != "auth-level error" {
		t.Fatalf("dtdErrorMessage(auth-level) = %q", msg)
	}
}

func TestClientCertRequested(t *testing.T) {
	if clientCertRequested(nil) {
		t.Fatal("clientCertRequested(nil) should be false")
	}
	if clientCertRequested(&proto.DTD{}) {
		t.Fatal("clientCertRequested(empty dtd) should be false")
	}
	d := &proto.DTD{ClientCertRequest: &struct{}{}}
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
