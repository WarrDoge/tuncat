package network

import "testing"

func TestNormalizeDNSDomains(t *testing.T) {
	t.Run("dedup_and_lowercase", func(t *testing.T) {
		input := []string{" Corp.Example.com ", ".internal.example.com", "", "corp.example.com", "INTERNAL.EXAMPLE.COM"}
		got := NormalizeDNSDomains(input)
		if len(got) != 2 {
			t.Fatalf("NormalizeDNSDomains len = %d, want 2 (%v)", len(got), got)
		}
		if got[0] != "corp.example.com" || got[1] != "internal.example.com" {
			t.Fatalf("NormalizeDNSDomains = %v, want [corp.example.com internal.example.com]", got)
		}
	})

	t.Run("empty_input", func(t *testing.T) {
		if got := NormalizeDNSDomains(nil); len(got) != 0 {
			t.Fatalf("NormalizeDNSDomains(nil) = %v, want empty", got)
		}
		if got := NormalizeDNSDomains([]string{}); len(got) != 0 {
			t.Fatalf("NormalizeDNSDomains([]) = %v, want empty", got)
		}
	})

	t.Run("all_empty_strings", func(t *testing.T) {
		if got := NormalizeDNSDomains([]string{"", " ", "\t", "."}); len(got) != 0 {
			t.Fatalf("NormalizeDNSDomains(all-empty) = %v, want empty", got)
		}
	})

	t.Run("leading_dot_stripped", func(t *testing.T) {
		got := NormalizeDNSDomains([]string{".sub.example.com"})
		if len(got) != 1 || got[0] != "sub.example.com" {
			t.Fatalf("NormalizeDNSDomains(.sub.example.com) = %v, want [sub.example.com]", got)
		}
	})

	t.Run("single_dot_becomes_empty", func(t *testing.T) {
		got := NormalizeDNSDomains([]string{"."})
		if len(got) != 0 {
			t.Fatalf("NormalizeDNSDomains(.) = %v, want empty", got)
		}
	})

	t.Run("preserves_order", func(t *testing.T) {
		input := []string{"b.example.com", "a.example.com"}
		got := NormalizeDNSDomains(input)
		if len(got) != 2 || got[0] != "b.example.com" || got[1] != "a.example.com" {
			t.Fatalf("NormalizeDNSDomains = %v, want [b.example.com a.example.com]", got)
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

func TestRouteToCIDREdgeCases(t *testing.T) {
	t.Run("trailing_dot_cidr", func(t *testing.T) {
		got, err := routeToCIDR("10.0.0.0/8 ")
		if err != nil {
			t.Fatalf("routeToCIDR with trailing space error: %v", err)
		}
		if got != "10.0.0.0/8" {
			t.Fatalf("routeToCIDR(trailing space) = %q, want 10.0.0.0/8", got)
		}
	})

	t.Run("slash_only_no_parts", func(t *testing.T) {
		if _, err := routeToCIDR("/"); err == nil {
			t.Fatal("routeToCIDR('/') expected error")
		}
	})

	t.Run("ip_with_mask_but_non_ip_second_part", func(t *testing.T) {
		if _, err := routeToCIDR("10.0.0.0/hello"); err == nil {
			t.Fatal("routeToCIDR with non-ip second part expected error")
		}
	})

	t.Run("just_whitespace", func(t *testing.T) {
		if _, err := routeToCIDR("  "); err == nil {
			t.Fatal("routeToCIDR(whitespace) expected error")
		}
	})
}
