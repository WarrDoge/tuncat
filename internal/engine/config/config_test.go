package config

import "testing"

func TestApplyDefaultsPreservesInsecureSkipVerifyTrue(t *testing.T) {
	cfg := &ClientConfig{InsecureSkipVerify: true}
	ApplyDefaults(cfg)
	if !cfg.InsecureSkipVerify {
		t.Fatal("ApplyDefaults overwrote InsecureSkipVerify=true")
	}
}

func TestApplyDefaultsPreservesCiscoCompatFalse(t *testing.T) {
	cfg := &ClientConfig{CiscoCompat: false}
	ApplyDefaults(cfg)
	if cfg.CiscoCompat {
		t.Fatal("ApplyDefaults overwrote CiscoCompat=false")
	}
}

func TestApplyDefaultsNilSafety(t *testing.T) {
	ApplyDefaults(nil)
	// Should not panic.
}

func TestApplyDefaultsSetsLogLevelWhenEmpty(t *testing.T) {
	cfg := &ClientConfig{}
	ApplyDefaults(cfg)
	if cfg.LogLevel != "Debug" {
		t.Fatalf("LogLevel = %q, want %q", cfg.LogLevel, "Debug")
	}
}
