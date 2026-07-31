package cli

import (
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeDNSServers(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{name: "nil input"},
		{name: "empty input", input: []string{}},
		{name: "single valid DNS", input: []string{"8.8.8.8"}, want: []string{"8.8.8.8"}},
		{name: "strips whitespace", input: []string{"  8.8.8.8  "}, want: []string{"8.8.8.8"}},
		{name: "skips empty strings", input: []string{"8.8.8.8", "", "1.1.1.1"}, want: []string{"8.8.8.8", "1.1.1.1"}},
		{name: "skips invalid IPs", input: []string{"8.8.8.8", "not-an-ip", "1.1.1.1"}, want: []string{"8.8.8.8", "1.1.1.1"}},
		{name: "deduplicates", input: []string{"8.8.8.8", "1.1.1.1", "8.8.8.8"}, want: []string{"8.8.8.8", "1.1.1.1"}},
		{name: "all invalid", input: []string{"bad", "", " "}},
		{name: "handles IPv6 addresses", input: []string{"2001:4860:4860::8888", "8.8.8.8"}, want: []string{"2001:4860:4860::8888", "8.8.8.8"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeDNSServers(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("normalizeDNSServers(%v) = %v (len %d), want %v (len %d)", tt.input, got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("normalizeDNSServers(%v)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestPortForURI(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "HTTPS default", raw: "https://example.com/health", want: "443"},
		{name: "HTTP default", raw: "http://example.com/health", want: "80"},
		{name: "explicit HTTP port", raw: "http://example.com:8080/health", want: "8080"},
		{name: "explicit HTTPS port", raw: "https://example.com:8443/health", want: "8443"},
		{name: "case-insensitive HTTPS", raw: "HTTPS://example.com/health", want: "443"},
		{name: "case-insensitive HTTP", raw: "HTTP://example.com/health", want: "80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.raw)
			if err != nil {
				t.Fatalf("invalid test URL %q: %v", tt.raw, err)
			}
			got := portForURI(u)
			if got != tt.want {
				t.Errorf("portForURI(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestVerifyEndpointEmptyHost(t *testing.T) {
	// A bare scheme "http://" parses successfully but has an empty hostname,
	// exercising the host-empty early-return path in verifyEndpoint.
	result := verifyEndpoint("http://", nil)
	if result.Error == "" || !strings.Contains(result.Error, "host is empty") {
		t.Fatalf("expected host-empty error, got: %q", result.Error)
	}
}
