package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfigFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("server: test\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func withWorkingDir(t *testing.T, dir string) {
	t.Helper()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})
}

func TestFindConfigFileSearchOrder(t *testing.T) {
	tmp := t.TempDir()
	withWorkingDir(t, tmp)

	writeConfigFile(t, filepath.Join(tmp, "config.yaml"))
	writeConfigFile(t, filepath.Join(tmp, ".tuncat", "config.yaml"))
	writeConfigFile(t, filepath.Join(tmp, "tuncat", "config.yaml"))

	got := findConfigFile("")
	want := filepath.Join("tuncat", "config.yaml")
	if got != want {
		t.Fatalf("findConfigFile() = %q, want %q", got, want)
	}
}

func TestFindConfigFileFallsBackToDotTuncat(t *testing.T) {
	tmp := t.TempDir()
	withWorkingDir(t, tmp)

	writeConfigFile(t, filepath.Join(tmp, ".tuncat", "config.yaml"))

	got := findConfigFile("")
	want := filepath.Join(".tuncat", "config.yaml")
	if got != want {
		t.Fatalf("findConfigFile() = %q, want %q", got, want)
	}
}

func TestFindConfigFileUsesHomeFallbacks(t *testing.T) {
	tmp := t.TempDir()
	withWorkingDir(t, tmp)

	home := filepath.Join(tmp, "home")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	writeConfigFile(t, filepath.Join(home, ".tuncat", "config.yaml"))

	got := findConfigFile("")
	want := filepath.Join(home, ".tuncat", "config.yaml")
	if got != want {
		t.Fatalf("findConfigFile() = %q, want %q", got, want)
	}
}

func TestFindConfigFileLegacyFallback(t *testing.T) {
	tmp := t.TempDir()
	withWorkingDir(t, tmp)

	writeConfigFile(t, filepath.Join(tmp, "config.yaml"))

	got := findConfigFile("")
	if got != "config.yaml" {
		t.Fatalf("findConfigFile() = %q, want %q", got, "config.yaml")
	}
}

func TestObscureRevealRoundTrip(t *testing.T) {
	passwords := []string{
		"simple",
		"p@ssw0rd!#$%",
		"",
		"a very long password with spaces and unicode: äöü日本語",
	}
	for _, pw := range passwords {
		enc, err := obscure(pw)
		if err != nil {
			t.Fatalf("obscure(%q): %v", pw, err)
		}
		dec, err := reveal(enc)
		if err != nil {
			t.Fatalf("reveal(%q): %v", enc, err)
		}
		if dec != pw {
			t.Errorf("round-trip failed: got %q, want %q", dec, pw)
		}
	}
}

func TestRevealPlaintext(t *testing.T) {
	plain := "not-obscured"
	got, err := reveal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Errorf("reveal plaintext: got %q, want %q", got, plain)
	}
}

func TestParseSplitRoute(t *testing.T) {
	tests := []struct {
		cidr    string
		addr    string
		masklen int
	}{
		{"10.0.0.0/8", "10.0.0.0", 8},
		{"172.16.0.0/12", "172.16.0.0", 12},
		{"192.168.1.0/24", "192.168.1.0", 24},
	}
	for _, tt := range tests {
		addr, masklen, err := parseSplitRoute(tt.cidr)
		if err != nil {
			t.Fatalf("parseSplitRoute(%q): %v", tt.cidr, err)
		}
		if addr != tt.addr || masklen != tt.masklen {
			t.Errorf("parseSplitRoute(%q) = (%q, %d), want (%q, %d)",
				tt.cidr, addr, masklen, tt.addr, tt.masklen)
		}
	}
}

func TestParseSplitRouteInvalid(t *testing.T) {
	_, _, err := parseSplitRoute("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestParseSplitRouteIPv6(t *testing.T) {
	_, _, err := parseSplitRoute("fd00::/8")
	if err == nil {
		t.Error("expected error for IPv6 CIDR")
	}
}

func TestNormalizeConfig(t *testing.T) {
	cfg := &Config{
		Server:     "  vpn.example.com  ",
		Username:   "  user  ",
		PfxPath:    "  /tmp/user.pfx  ",
		VerifyURL:  "  https://vpn.example.com/health  ",
		DNSDomains: []string{" Corp.Example.com ", "", " .internal.example.com ", "corp.example.com"},
	}

	normalizeConfig(cfg)

	if cfg.Server != "vpn.example.com" {
		t.Fatalf("server not normalized: %q", cfg.Server)
	}
	if cfg.Username != "user" {
		t.Fatalf("username not normalized: %q", cfg.Username)
	}
	if cfg.PfxPath != "/tmp/user.pfx" {
		t.Fatalf("pfx_path not normalized: %q", cfg.PfxPath)
	}
	if cfg.VerifyURL != "https://vpn.example.com/health" {
		t.Fatalf("verify_url not normalized: %q", cfg.VerifyURL)
	}
	if len(cfg.DNSDomains) != 2 {
		t.Fatalf("dns_domains not normalized: %#v", cfg.DNSDomains)
	}
	if cfg.DNSDomains[0] != "corp.example.com" || cfg.DNSDomains[1] != "internal.example.com" {
		t.Fatalf("dns_domains values not normalized: %#v", cfg.DNSDomains)
	}
}

func TestValidateConfig(t *testing.T) {
	dir := t.TempDir()
	pfx := filepath.Join(dir, "user.pfx")
	if err := os.WriteFile(pfx, []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Server:      "vpn.example.com",
		Username:    "user",
		PfxPath:     pfx,
		BaseMTU:     1200,
		VerifyURL:   "https://vpn.example.com/health",
		SplitRoutes: []string{"10.0.0.0/8"},
		DNSDomains:  []string{"corp.example.com"},
	}

	if errs := validateConfig(cfg); len(errs) != 0 {
		t.Fatalf("expected no validation errors, got: %v", errs)
	}

	bad := &Config{
		BaseMTU:     100,
		SplitRoutes: []string{"bad-cidr"},
		DNSDomains:  []string{"bad domain"},
	}

	if errs := validateConfig(bad); len(errs) == 0 {
		t.Fatal("expected validation errors")
	}

	bad.VerifyURL = "ftp://vpn.example.com/health"
	if errs := validateConfig(bad); len(errs) == 0 {
		t.Fatal("expected verify_url validation errors")
	}
}

func TestVerifyEndpointSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
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
	if !result.HTTPOK() {
		t.Fatal("verifyEndpoint should report HTTP success")
	}
	if result.Duration <= 0 {
		t.Fatalf("duration = %v, want > 0", result.Duration)
	}
}

func TestVerifyEndpointInvalidURL(t *testing.T) {
	result := verifyEndpoint("://bad", nil)
	if result.Error == "" || !strings.Contains(result.Error, "invalid verify_url") {
		t.Fatalf("unexpected error: %q", result.Error)
	}
}

func TestVerifyEndpointUnsupportedScheme(t *testing.T) {
	result := verifyEndpoint("ftp://vpn.example.com/health", nil)
	if result.Error == "" || !strings.Contains(result.Error, "unsupported verify_url scheme") {
		t.Fatalf("unexpected error: %q", result.Error)
	}
}

func TestObscureConfigSecretsInFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	input := strings.Join([]string{
		`server: "vpn.example.com/group"`,
		`password: "plain-password"`,
		`pfx_password: "plain-pfx-password"`,
		`username: "user"`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}

	changed, err := obscureConfigSecretsInFile(path, map[string]bool{})
	if err != nil {
		t.Fatalf("obscureConfigSecretsInFile error: %v", err)
	}
	if !changed {
		t.Fatal("expected config write-back to change plaintext secrets")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	if strings.Contains(content, "plain-password") || strings.Contains(content, "plain-pfx-password") {
		t.Fatalf("plaintext secrets remained in file:\n%s", content)
	}
	if !strings.Contains(content, `password: obscured:`) {
		t.Fatalf("password was not obscured:\n%s", content)
	}
	if !strings.Contains(content, `pfx_password: obscured:`) {
		t.Fatalf("pfx_password was not obscured:\n%s", content)
	}
}

func TestObscureConfigSecretsInFileSkipsCLIOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	input := strings.Join([]string{
		`server: "vpn.example.com/group"`,
		`password: "plain-password"`,
		`pfx_password: "plain-pfx-password"`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}

	changed, err := obscureConfigSecretsInFile(path, map[string]bool{
		"password":     true,
		"pfx-password": true,
	})
	if err != nil {
		t.Fatalf("obscureConfigSecretsInFile error: %v", err)
	}
	if changed {
		t.Fatal("expected CLI overrides to skip config write-back")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	if !strings.Contains(content, `password: "plain-password"`) {
		t.Fatalf("password should remain plaintext when overridden by CLI:\n%s", content)
	}
	if !strings.Contains(content, `pfx_password: "plain-pfx-password"`) {
		t.Fatalf("pfx_password should remain plaintext when overridden by CLI:\n%s", content)
	}
}

func TestSplitServerForVPNCore(t *testing.T) {
	tests := []struct {
		in        string
		wantHost  string
		wantGroup string
		wantPath  string
	}{
		{in: "vpn.example.com/external", wantHost: "vpn.example.com", wantGroup: "external", wantPath: "/external"},
		{in: "https://vpn.example.com/engineering", wantHost: "vpn.example.com", wantGroup: "engineering", wantPath: "/engineering"},
		{in: "vpn.example.com", wantHost: "vpn.example.com", wantGroup: "", wantPath: "/"},
		{in: "vpn.example.com/team-external?foo=bar", wantHost: "vpn.example.com", wantGroup: "team-external", wantPath: "/team-external?foo=bar"},
	}

	for _, tc := range tests {
		target, err := splitServerForVPNCore(tc.in)
		if err != nil {
			t.Fatalf("splitServerForVPNCore(%q): %v", tc.in, err)
		}
		if target.Host != tc.wantHost || target.Group != tc.wantGroup || target.BasePath != tc.wantPath {
			t.Fatalf("splitServerForVPNCore(%q) = (%q,%q,%q), want (%q,%q,%q)", tc.in, target.Host, target.Group, target.BasePath, tc.wantHost, tc.wantGroup, tc.wantPath)
		}
	}
}

func TestSplitServerForVPNCoreEmpty(t *testing.T) {
	_, err := splitServerForVPNCore("  ")
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty server error, got: %v", err)
	}
}

func TestLoadConfigDefaultsWhenPathEmpty(t *testing.T) {
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig(empty) error: %v", err)
	}
	if cfg.Protocol != "anyconnect" {
		t.Fatalf("default protocol = %q, want anyconnect", cfg.Protocol)
	}
	if cfg.UserAgent != "AnyConnect" {
		t.Fatalf("default user_agent = %q, want AnyConnect", cfg.UserAgent)
	}
	if cfg.BaseMTU != 1200 {
		t.Fatalf("default base_mtu = %d, want 1200", cfg.BaseMTU)
	}
}

func TestLoadConfigResolvesRelativePFXPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	relPfx := filepath.Join("certs", "client.pfx")

	content := strings.Join([]string{
		"server: vpn.example.com",
		"username: user",
		"pfx_path: " + relPfx,
	}, "\n")
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig error: %v", err)
	}
	want := filepath.Join(dir, relPfx)
	if cfg.PfxPath != want {
		t.Fatalf("resolved pfx_path = %q, want %q", cfg.PfxPath, want)
	}
}
