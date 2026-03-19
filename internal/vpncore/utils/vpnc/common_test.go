package vpnc

import "testing"

func TestNormalizeDNSDomains(t *testing.T) {
	input := []string{" Corp.Example.com ", ".internal.example.com", "", "corp.example.com", "INTERNAL.EXAMPLE.COM"}
	got := NormalizeDNSDomains(input)
	if len(got) != 2 {
		t.Fatalf("NormalizeDNSDomains len = %d, want 2 (%v)", len(got), got)
	}
	if got[0] != "corp.example.com" || got[1] != "internal.example.com" {
		t.Fatalf("NormalizeDNSDomains = %v, want [corp.example.com internal.example.com]", got)
	}
}

func TestRouteToCIDRVariants(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "10.0.0.0/8", want: "10.0.0.0/8"},
		{in: "10.0.0.0/255.0.0.0", want: "10.0.0.0/8"},
		{in: "192.168.1.0/255.255.255.0", want: "192.168.1.0/24"},
	}

	for _, tt := range tests {
		got, err := routeToCIDR(tt.in)
		if err != nil {
			t.Fatalf("routeToCIDR(%q) error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("routeToCIDR(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRouteToCIDRInvalid(t *testing.T) {
	bad := []string{"", "not-a-route", "10.0.0.0/255.0.0", "10.0.0.0/abc"}
	for _, in := range bad {
		if _, err := routeToCIDR(in); err == nil {
			t.Fatalf("routeToCIDR(%q) expected error", in)
		}
	}
}
