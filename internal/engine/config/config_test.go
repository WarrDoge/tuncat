package config

import (
	"net"
	"strings"
	"testing"
)

// TestApplyDefaultsBaseMTU verifies that ApplyDefaults sets a valid BaseMTU
// when zero, and preserves an already-set value.
func TestApplyDefaultsBaseMTU(t *testing.T) {
	// Zero BaseMTU should get the default (1200), which must be > 576.
	cfg := &ClientConfig{}
	ApplyDefaults(cfg)
	if cfg.BaseMTU < 576 || cfg.BaseMTU > 20000 {
		t.Errorf("ApplyDefaults BaseMTU = %d, want in [576, 20000]", cfg.BaseMTU)
	}

	// User-set value in the valid range must be preserved.
	cfg2 := &ClientConfig{BaseMTU: 1400}
	ApplyDefaults(cfg2)
	if cfg2.BaseMTU != 1400 {
		t.Errorf("ApplyDefaults preserved BaseMTU = %d, want 1400", cfg2.BaseMTU)
	}
}

// TestApplyDefaultsRPCAddr verifies that ApplyDefaults sets a parseable RPCAddr
// when empty, and preserves an already-set valid address.
func TestApplyDefaultsRPCAddr(t *testing.T) {
	// Empty RPCAddr should get the default "127.0.0.1:6210" which must parse.
	cfg := &ClientConfig{}
	ApplyDefaults(cfg)
	if _, _, err := net.SplitHostPort(cfg.RPCAddr); err != nil {
		t.Errorf("ApplyDefaults RPCAddr %q not parseable: %v", cfg.RPCAddr, err)
	}

	// User-set non-empty value must be preserved (even if invalid — consumers
	// like normalizeRPCAddr do their own validation).
	cfg2 := &ClientConfig{RPCAddr: "[::1]:9999"}
	ApplyDefaults(cfg2)
	if cfg2.RPCAddr != "[::1]:9999" {
		t.Errorf("ApplyDefaults preserved RPCAddr = %q, want %q", cfg2.RPCAddr, "[::1]:9999")
	}
}

// TestApplyDefaultsLogLevel verifies that ApplyDefaults sets a known log level
// when empty, and preserves an already-set value.
func TestApplyDefaultsLogLevel(t *testing.T) {
	// Empty LogLevel should get "Debug", which must be one of the known levels
	// that logLevel2Int can parse.
	cfg := &ClientConfig{}
	ApplyDefaults(cfg)
	knownLevels := []string{"Debug", "Info", "Warn", "Error", "Fatal"}
	var matched bool
	for _, l := range knownLevels {
		if strings.EqualFold(cfg.LogLevel, l) {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("ApplyDefaults LogLevel = %q, want one of %v", cfg.LogLevel, knownLevels)
	}

	// User-set value must be preserved (even if unrecognized — logLevel2Int
	// falls back to Info).
	cfg2 := &ClientConfig{LogLevel: "Warn"}
	ApplyDefaults(cfg2)
	if cfg2.LogLevel != "Warn" {
		t.Errorf("ApplyDefaults preserved LogLevel = %q, want %q", cfg2.LogLevel, "Warn")
	}
}

// TestApplyDefaultsSplitRoutes verifies that ApplyDefaults passes through
// SplitRoutes unchanged (no normalization, no validation).
func TestApplyDefaultsSplitRoutes(t *testing.T) {
	// Nil slice stays nil.
	cfg := &ClientConfig{}
	ApplyDefaults(cfg)
	if cfg.SplitRoutes != nil {
		t.Errorf("ApplyDefaults SplitRoutes = %v, want nil", cfg.SplitRoutes)
	}

	// Preset routes pass through untouched.
	routes := []string{"10.0.0.0/8", "invalid", "172.16.0.0/12"}
	cfg2 := &ClientConfig{SplitRoutes: routes}
	ApplyDefaults(cfg2)
	if len(cfg2.SplitRoutes) != 3 {
		t.Fatalf("ApplyDefaults SplitRoutes len = %d, want 3", len(cfg2.SplitRoutes))
	}
	for i, r := range cfg2.SplitRoutes {
		if r != routes[i] {
			t.Errorf("ApplyDefaults SplitRoutes[%d] = %q, want %q", i, r, routes[i])
		}
	}
}

// TestApplyDefaultsDNSDomains verifies that ApplyDefaults passes through
// DNSDomains unchanged (normalization is in network.NormalizeDNSDomains).
func TestApplyDefaultsDNSDomains(t *testing.T) {
	// Nil slice stays nil.
	cfg := &ClientConfig{}
	ApplyDefaults(cfg)
	if cfg.DNSDomains != nil {
		t.Errorf("ApplyDefaults DNSDomains = %v, want nil", cfg.DNSDomains)
	}

	// Preset domains pass through unchanged (normalization is the consumer's job).
	domains := []string{" Corp.Example.com ", ""}
	cfg2 := &ClientConfig{DNSDomains: domains}
	ApplyDefaults(cfg2)
	if len(cfg2.DNSDomains) != 2 {
		t.Fatalf("ApplyDefaults DNSDomains len = %d, want 2", len(cfg2.DNSDomains))
	}
	if cfg2.DNSDomains[0] != " Corp.Example.com " {
		t.Errorf("ApplyDefaults DNSDomains[0] = %q, want %q", cfg2.DNSDomains[0], " Corp.Example.com ")
	}
}

// TestApplyDefaultsInsecureSkipVerify verifies that ApplyDefaults
// resets InsecureSkipVerify to false.
func TestApplyDefaultsInsecureSkipVerify(t *testing.T) {
	// Default — not set, should be false.
	cfg := &ClientConfig{}
	ApplyDefaults(cfg)
	if cfg.InsecureSkipVerify {
		t.Error("ApplyDefaults InsecureSkipVerify = true, want false")
	}

	// If someone sets it true, ApplyDefaults overrides to false.
	cfg2 := &ClientConfig{InsecureSkipVerify: true}
	ApplyDefaults(cfg2)
	if cfg2.InsecureSkipVerify {
		t.Error("ApplyDefaults should override InsecureSkipVerify to false")
	}
}

// TestApplyDefaultsCiscoCompat verifies that ApplyDefaults
// sets CiscoCompat to true.
func TestApplyDefaultsCiscoCompat(t *testing.T) {
	// Default — not set, should be true.
	cfg := &ClientConfig{}
	ApplyDefaults(cfg)
	if !cfg.CiscoCompat {
		t.Error("ApplyDefaults CiscoCompat = false, want true")
	}

	// If someone sets it false, ApplyDefaults overrides to true.
	cfg2 := &ClientConfig{CiscoCompat: false}
	ApplyDefaults(cfg2)
	if !cfg2.CiscoCompat {
		t.Error("ApplyDefaults should override CiscoCompat to true")
	}
}

// TestApplyDefaultsAgentNameAndVersion verifies that ApplyDefaults
// sets agent name/version to non-empty strings.
func TestApplyDefaultsAgentNameAndVersion(t *testing.T) {
	cfg := &ClientConfig{}
	ApplyDefaults(cfg)
	if cfg.AgentName == "" {
		t.Error("ApplyDefaults AgentName is empty")
	}
	if cfg.AgentVersion == "" {
		t.Error("ApplyDefaults AgentVersion is empty")
	}

	// User-set values are preserved.
	cfg2 := &ClientConfig{AgentName: "CustomAgent", AgentVersion: "1.0"}
	ApplyDefaults(cfg2)
	if cfg2.AgentName != "CustomAgent" {
		t.Errorf("ApplyDefaults preserved AgentName = %q, want %q", cfg2.AgentName, "CustomAgent")
	}
	if cfg2.AgentVersion != "1.0" {
		t.Errorf("ApplyDefaults preserved AgentVersion = %q, want %q", cfg2.AgentVersion, "1.0")
	}
}

// TestApplyDefaultsNil verifies that ApplyDefaults handles a nil config
// without panicking.
func TestApplyDefaultsNil(t *testing.T) {
	ApplyDefaults(nil)
	// Must not panic.
}

// TestNewClientConfig verifies that NewClientConfig returns a fully-defaulted
// config with all producer-side guarantees met.
func TestNewClientConfig(t *testing.T) {
	cfg := NewClientConfig()
	if cfg == nil {
		t.Fatal("NewClientConfig() returned nil")
	}
	if cfg.BaseMTU < 576 || cfg.BaseMTU > 20000 {
		t.Errorf("BaseMTU = %d, want in [576, 20000]", cfg.BaseMTU)
	}
	if _, _, err := net.SplitHostPort(cfg.RPCAddr); err != nil {
		t.Errorf("RPCAddr %q not parseable: %v", cfg.RPCAddr, err)
	}
	if cfg.LogLevel == "" {
		t.Error("LogLevel is empty")
	}
	if cfg.AgentName == "" {
		t.Error("AgentName is empty")
	}
	if cfg.AgentVersion == "" {
		t.Error("AgentVersion is empty")
	}
}
