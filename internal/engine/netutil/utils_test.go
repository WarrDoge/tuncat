package netutil

import "testing"

func TestInArray(t *testing.T) {
	if !InArray([]string{"a", "b"}, "b") {
		t.Fatal("expected true for existing element")
	}
	if InArray([]string{"a", "b"}, "c") {
		t.Fatal("expected false for missing element")
	}
}

func TestInArrayGenericSuffixMatch(t *testing.T) {
	if !InArrayGeneric([]string{"example.com"}, "api.example.com") {
		t.Fatal("expected suffix match")
	}
	if InArrayGeneric([]string{"example.com"}, "api.example.net") {
		t.Fatal("unexpected suffix match")
	}
}

func TestIPMaskHelpers(t *testing.T) {
	if got := IpMask2CIDR("10.0.0.1", "255.255.255.0"); got != "10.0.0.1/24" {
		t.Fatalf("IpMask2CIDR = %q, want %q", got, "10.0.0.1/24")
	}
	if got := IpMaskToCIDR("10.0.0.0/255.0.0.0"); got != "10.0.0.0/8" {
		t.Fatalf("IpMaskToCIDR = %q, want %q", got, "10.0.0.0/8")
	}
}

func TestMinMax(t *testing.T) {
	if got := Min(100, 50, 80); got != 50 {
		t.Fatalf("Min = %d, want 50", got)
	}
	if got := Max(10, 20, 15); got != 20 {
		t.Fatalf("Max = %d, want 20", got)
	}
}

func TestFirstUpper(t *testing.T) {
	if got := FirstUpper("linux_amd64"); got != "Linux_amd64" {
		t.Fatalf("FirstUpper = %q, want %q", got, "Linux_amd64")
	}
	if got := FirstUpper(""); got != "" {
		t.Fatalf("FirstUpper empty = %q, want empty", got)
	}
}

func TestRemoveBetween(t *testing.T) {
	in := "before<auth>secret\nsecret2</auth>after"
	got := RemoveBetween(in, "<auth>", "</auth>")
	if got != "beforeafter" {
		t.Fatalf("RemoveBetween = %q, want %q", got, "beforeafter")
	}
}
