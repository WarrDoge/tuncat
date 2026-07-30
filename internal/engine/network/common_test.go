package network

import "testing"

func TestNormalizeDNSDomains(t *testing.T) {
	t.Run("dedup and lowercase", func(t *testing.T) {
		input := []string{" Corp.Example.com ", ".internal.example.com", "", "corp.example.com", "INTERNAL.EXAMPLE.COM"}
		got := NormalizeDNSDomains(input)
		if len(got) != 2 {
			t.Fatalf("NormalizeDNSDomains len = %d, want 2 (%v)", len(got), got)
		}
		if got[0] != "corp.example.com" || got[1] != "internal.example.com" {
			t.Fatalf("NormalizeDNSDomains = %v, want [corp.example.com internal.example.com]", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		got := NormalizeDNSDomains(nil)
		if len(got) != 0 {
			t.Fatalf("expected nil/empty output, got %v", got)
		}
		got = NormalizeDNSDomains([]string{})
		if len(got) != 0 {
			t.Fatalf("expected empty output, got %v", got)
		}
	})

	t.Run("whitespace only", func(t *testing.T) {
		got := NormalizeDNSDomains([]string{"  ", "\t", " \n "})
		if len(got) != 0 {
			t.Fatalf("expected empty output for whitespace-only input, got %v", got)
		}
	})

	t.Run("leading dot stripped", func(t *testing.T) {
		got := NormalizeDNSDomains([]string{".example.com", "..double.example.com"})
		if len(got) != 2 {
			t.Fatalf("expected 2 domains, got %v", got)
		}
		if got[0] != "example.com" {
			t.Fatalf("got[0] = %q, want %q", got[0], "example.com")
		}
		if got[1] != ".double.example.com" {
			t.Fatalf("got[1] = %q, want %q", got[1], ".double.example.com")
		}
	})

	t.Run("case insensitive dedup", func(t *testing.T) {
		got := NormalizeDNSDomains([]string{"Example.COM", "example.com"})
		if len(got) != 1 {
			t.Fatalf("expected 1 domain after case-insensitive dedup, got %v", got)
		}
	})
}

func TestRouteToCIDRVariants(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "10.0.0.0/8", want: "10.0.0.0/8"},
		{in: "10.0.0.0/255.0.0.0", want: "10.0.0.0/8"},
		{in: "192.168.1.0/255.255.255.0", want: "192.168.1.0/24"},
		{in: "  10.0.0.0/8  ", want: "10.0.0.0/8"},
		{in: "172.16.0.0/255.255.0.0", want: "172.16.0.0/16"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := routeToCIDR(tt.in)
			if err != nil {
				t.Fatalf("routeToCIDR(%q) error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("routeToCIDR(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRouteToCIDRInvalid(t *testing.T) {
	bad := []string{
		"",
		"not-a-route",
		"10.0.0.0/255.0.0",
		"10.0.0.0/abc",
		"10.0.0.0/",
		"/8",
		"10.0.0.0/256.0.0.0",
	}
	for _, in := range bad {
		t.Run(in, func(t *testing.T) {
			if _, err := routeToCIDR(in); err == nil {
				t.Fatalf("routeToCIDR(%q) expected error", in)
			}
		})
	}
}
