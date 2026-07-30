package network

import (
	"net"
	"testing"
)

func TestRoutingError(t *testing.T) {
	_, dst, _ := net.ParseCIDR("10.0.0.0/8")
	original := routingError(dst, nil)

	// routingError formats as "routing error: <dst> <err>"
	if original == nil || original.Error() == "" {
		t.Fatal("routingError returned nil/empty")
	}

	err := routingError(dst, original)
	if err.Error() == "" {
		t.Fatal("routingError wrapped error returned empty")
	}
}

func TestRoutingErrorWithNonNilError(t *testing.T) {
	_, dst, _ := net.ParseCIDR("192.168.1.0/24")
	base := routingError(dst, nil)
	err := routingError(dst, base)
	if err.Error() == "" {
		t.Fatal("routingError wrapped error returned empty")
	}
}

func TestRouteToCIDRMoreEdges(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
	}{
		{in: "0.0.0.0/0", wantErr: false},
		{in: "0.0.0.0/0.0.0.0", wantErr: false},
		{in: "10.0.0.0/255.0.0.0", wantErr: false},
		{in: "/24", wantErr: true},
		{in: "10.0.0.0", wantErr: true}, // missing mask
	}

	for _, tt := range tests {
		_, err := routeToCIDR(tt.in)
		if tt.wantErr && err == nil {
			t.Fatalf("routeToCIDR(%q) expected error", tt.in)
		}
		if !tt.wantErr && err != nil {
			t.Fatalf("routeToCIDR(%q) unexpected error: %v", tt.in, err)
		}
	}
}

func TestRouteToCIDRExplicitMask(t *testing.T) {
	got, err := routeToCIDR("172.16.0.0/255.255.0.0")
	if err != nil {
		t.Fatalf("routeToCIDR(172.16.0.0/255.255.0.0) error: %v", err)
	}
	if got != "172.16.0.0/16" {
		t.Fatalf("routeToCIDR = %q, want 172.16.0.0/16", got)
	}
}

func TestNormalizeDNSDomainsWithDots(t *testing.T) {
	got := NormalizeDNSDomains([]string{".example.com", ".corp.example.com", ".example.com"})
	if len(got) != 2 {
		t.Fatalf("NormalizeDNSDomains len = %d, want 2 (%v)", len(got), got)
	}
	if got[0] != "example.com" || got[1] != "corp.example.com" {
		t.Fatalf("NormalizeDNSDomains = %v, want [example.com corp.example.com]", got)
	}
}

func TestNormalizeDNSDomainsEmptyInput(t *testing.T) {
	got := NormalizeDNSDomains(nil)
	if len(got) != 0 {
		t.Fatalf("NormalizeDNSDomains(nil) = %v, want empty", got)
	}

	got = NormalizeDNSDomains([]string{})
	if len(got) != 0 {
		t.Fatalf("NormalizeDNSDomains([]) = %v, want empty", got)
	}
}
