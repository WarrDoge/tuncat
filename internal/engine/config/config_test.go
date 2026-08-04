package config

import (
	"testing"
)

func TestValidateBaseMTU_BelowMin(t *testing.T) {
	cfg := &ClientConfig{BaseMTU: 100}
	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Fatal("expected error for BaseMTU=100, got none")
	}
}

func TestValidateBaseMTU_AboveMax(t *testing.T) {
	cfg := &ClientConfig{BaseMTU: 30000}
	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Fatal("expected error for BaseMTU=30000, got none")
	}
}

func TestValidateBaseMTU_ZeroIsValid(t *testing.T) {
	cfg := &ClientConfig{BaseMTU: 0}
	errs := cfg.Validate()
	for _, e := range errs {
		t.Logf("unexpected error: %v", e)
	}
	if len(errs) != 0 {
		t.Fatal("expected no errors for BaseMTU=0 (means default)")
	}
}

func TestValidateBaseMTU_ValidRange(t *testing.T) {
	cfg := &ClientConfig{BaseMTU: 1500}
	errs := cfg.Validate()
	for _, e := range errs {
		t.Logf("unexpected error: %v", e)
	}
	if len(errs) != 0 {
		t.Fatal("expected no errors for BaseMTU=1500")
	}
}

func TestValidateSplitRoutes_InvalidCIDR(t *testing.T) {
	cfg := &ClientConfig{SplitRoutes: []string{"not-a-cidr"}}
	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Fatal("expected error for invalid CIDR, got none")
	}
}

func TestValidateSplitRoutes_IPv6Unsupported(t *testing.T) {
	cfg := &ClientConfig{SplitRoutes: []string{"::1/128"}}
	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Fatal("expected error for IPv6 CIDR, got none")
	}
}

func TestValidateSplitRoutes_Valid(t *testing.T) {
	cfg := &ClientConfig{SplitRoutes: []string{"10.0.0.0/8", "192.168.1.0/24"}}
	errs := cfg.Validate()
	for _, e := range errs {
		t.Logf("unexpected error: %v", e)
	}
	if len(errs) != 0 {
		t.Fatal("expected no errors for valid split routes")
	}
}

func TestValidateRPCAddr_NoPort(t *testing.T) {
	cfg := &ClientConfig{RPCAddr: "127.0.0.1"}
	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Fatal("expected error for RPCAddr with no port, got none")
	}
}

func TestValidateRPCAddr_EmptyIsValid(t *testing.T) {
	cfg := &ClientConfig{RPCAddr: ""}
	errs := cfg.Validate()
	for _, e := range errs {
		t.Logf("unexpected error: %v", e)
	}
	if len(errs) != 0 {
		t.Fatal("expected no errors for empty RPCAddr (ApplyDefaults fills it)")
	}
}

func TestValidateRPCAddr_WithPort(t *testing.T) {
	cfg := &ClientConfig{RPCAddr: "127.0.0.1:6210"}
	errs := cfg.Validate()
	for _, e := range errs {
		t.Logf("unexpected error: %v", e)
	}
	if len(errs) != 0 {
		t.Fatal("expected no errors for valid RPCAddr")
	}
}

func TestValidateLogLevel_Unknown(t *testing.T) {
	cfg := &ClientConfig{LogLevel: "verbose"}
	errs := cfg.Validate()
	if len(errs) == 0 {
		t.Fatal("expected error for unknown log level, got none")
	}
}

func TestValidateLogLevel_EmptyIsValid(t *testing.T) {
	cfg := &ClientConfig{LogLevel: ""}
	errs := cfg.Validate()
	for _, e := range errs {
		t.Logf("unexpected error: %v", e)
	}
	if len(errs) != 0 {
		t.Fatal("expected no errors for empty LogLevel (ApplyDefaults fills it)")
	}
}

func TestValidateLogLevel_ValidLevels(t *testing.T) {
	levels := []string{"Debug", "Info", "Warn", "Error", "Fatal"}
	for _, lvl := range levels {
		cfg := &ClientConfig{LogLevel: lvl}
		errs := cfg.Validate()
		if len(errs) != 0 {
			t.Fatalf("expected no errors for LogLevel=%q, got %v", lvl, errs)
		}
	}
}

func TestValidateLogLevel_CaseInsensitive(t *testing.T) {
	cfg := &ClientConfig{LogLevel: "debug"}
	errs := cfg.Validate()
	if len(errs) != 0 {
		t.Fatalf("expected no errors for LogLevel=debug (lowercase), got %v", errs)
	}
}

// TestValidate_GoodConfig verifies a fully-populated valid config passes.
func TestValidate_GoodConfig(t *testing.T) {
	cfg := &ClientConfig{
		LogLevel:  "Info",
		RPCAddr:   "127.0.0.1:6210",
		BaseMTU:   1200,
		SplitRoutes: []string{"10.0.0.0/8"},
	}
	errs := cfg.Validate()
	if len(errs) != 0 {
		t.Fatalf("expected no errors for valid config, got %v", errs)
	}
}
