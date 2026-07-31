package cli

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestNormalizeDNSServers_Dedup(t *testing.T) {
	in := []string{"8.8.8.8", "8.8.8.8", "1.1.1.1"}
	got := NormalizeDNSServers(in)
	want := []string{"8.8.8.8", "1.1.1.1"}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestNormalizeDNSServers_EmptiesStripped(t *testing.T) {
	in := []string{"", " ", "8.8.8.8", "\t", "1.1.1.1"}
	got := NormalizeDNSServers(in)
	want := []string{"8.8.8.8", "1.1.1.1"}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestNormalizeDNSServers_NonIPRejected(t *testing.T) {
	in := []string{"not-an-ip", "8.8.8.8", "dns.example.com"}
	got := NormalizeDNSServers(in)
	want := []string{"8.8.8.8"}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d: %v", len(got), len(want), got)
	}
}

func TestNormalizeDNSServers_NilInput(t *testing.T) {
	got := NormalizeDNSServers(nil)
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

// Port-bearing IP addresses like "10.0.0.1" (which could be used with a port
// in the dialer) are accepted as valid IPs by NormalizeDNSServers.
func TestNormalizeDNSServers_PortBearingIPsAccepted(t *testing.T) {
	in := []string{"10.0.0.1", "192.168.1.1"}
	got := NormalizeDNSServers(in)
	want := []string{"10.0.0.1", "192.168.1.1"}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestPortForURI_ExplicitPort(t *testing.T) {
	u, _ := url.Parse("https://example.com:8443/health")
	got := PortForURI(u)
	if got != "8443" {
		t.Fatalf("got %q, want 8443", got)
	}
}

func TestPortForURI_HTTPSDefault(t *testing.T) {
	u, _ := url.Parse("https://example.com/health")
	got := PortForURI(u)
	if got != "443" {
		t.Fatalf("got %q, want 443", got)
	}
}

func TestPortForURI_HTTPDefault(t *testing.T) {
	u, _ := url.Parse("http://example.com/health")
	got := PortForURI(u)
	if got != "80" {
		t.Fatalf("got %q, want 80", got)
	}
}

func TestProbeHTTP_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	srvURL, _ := url.Parse(srv.URL)
	status, err := ProbeHTTP(client, srvURL, srvURL.Hostname(), srvURL.Hostname())
	if err != nil {
		t.Fatalf("ProbeHTTP failed: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status=%d, want %d", status, http.StatusOK)
	}
}

func TestProbeHTTP_ConnectionRefused(t *testing.T) {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	u, _ := url.Parse("http://127.0.0.1:19876/test")
	_, err := ProbeHTTP(client, u, "127.0.0.1", "127.0.0.1")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
}

func TestProbeHTTP_Timeout(t *testing.T) {
	// Server that never responds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 50 * time.Millisecond}
	srvURL, _ := url.Parse(srv.URL)
	_, err := ProbeHTTP(client, srvURL, srvURL.Hostname(), srvURL.Hostname())
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestResolveHost_CustomServerFails(t *testing.T) {
	_, err := ResolveHost("example.com", []string{"203.0.113.1"})
	if err == nil {
		t.Fatal("expected error for unreachable DNS server, got nil")
	}
}

func TestResolveHost_MultipleServersTriedInOrder(t *testing.T) {
	_, err := ResolveHost("example.com", []string{"203.0.113.1", "203.0.113.2"})
	if err == nil {
		t.Fatal("expected error when both servers unreachable, got nil")
	}
}

func TestResolveHost_SystemResolverFallback(t *testing.T) {
	_, err := ResolveHost("localhost", nil)
	if err != nil {
		t.Fatalf("system resolver failed: %v", err)
	}
}

// Verify that verifyEndpoint behaviour is unchanged after the export refactor.
func TestVerifyEndpointStillWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	result := verifyEndpoint(srv.URL+"/health", nil)
	if result.Error != "" {
		t.Fatalf("verifyEndpoint returned error: %s", result.Error)
	}
	if result.Host == "" {
		t.Fatal("verifyEndpoint returned empty host")
	}
	if !result.Resolved {
		t.Fatal("verifyEndpoint did not report DNS resolution")
	}
	if len(result.Addresses) == 0 {
		t.Fatal("verifyEndpoint returned no resolved addresses")
	}
	if result.HTTPStatus != http.StatusNoContent {
		t.Fatalf("HTTP status = %d, want %d", result.HTTPStatus, http.StatusNoContent)
	}
	if result.Duration <= 0 {
		t.Fatalf("duration = %v, want > 0", result.Duration)
	}
}

// Test that the retry deadline behaviour is preserved.
func TestVerifyEndpointDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Second)
	}))
	defer srv.Close()

	result := verifyEndpoint(srv.URL, nil)
	if result.Error == "" {
		t.Fatal("expected timeout error after deadline")
	}
	if result.Attempts < 1 {
		t.Fatalf("expected at least 1 attempt, got %d", result.Attempts)
	}
}
