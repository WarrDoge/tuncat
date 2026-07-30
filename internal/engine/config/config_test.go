package config

import (
	"testing"
)

func TestNewClientConfigAppliesDefaults(t *testing.T) {
	cfg := NewClientConfig()
	if cfg.LogLevel != "Debug" {
		t.Fatalf("LogLevel = %q, want %q", cfg.LogLevel, "Debug")
	}
	if cfg.RPCAddr != "127.0.0.1:6210" {
		t.Fatalf("RPCAddr = %q, want %q", cfg.RPCAddr, "127.0.0.1:6210")
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should be false")
	}
	if !cfg.CiscoCompat {
		t.Fatal("CiscoCompat should be true")
	}
	if cfg.AgentName != "AnyConnect" {
		t.Fatalf("AgentName = %q, want %q", cfg.AgentName, "AnyConnect")
	}
	if cfg.AgentVersion != "4.10.07062" {
		t.Fatalf("AgentVersion = %q, want %q", cfg.AgentVersion, "4.10.07062")
	}
	if cfg.BaseMTU != 1200 {
		t.Fatalf("BaseMTU = %d, want %d", cfg.BaseMTU, 1200)
	}
}

func TestNewClientConfigNilSafe(t *testing.T) {
	// ApplyDefaults handles nil without panicking.
	ApplyDefaults(nil)
}

func TestNewClientConfigSkipsExistingValues(t *testing.T) {
	cfg := &ClientConfig{
		LogLevel:     "Info",
		RPCAddr:      "10.0.0.1:9999",
		AgentName:    "CustomAgent",
		AgentVersion: "1.0.0",
		BaseMTU:      1500,
	}
	ApplyDefaults(cfg)

	if cfg.LogLevel != "Info" {
		t.Fatalf("LogLevel should stay 'Info', got %q", cfg.LogLevel)
	}
	if cfg.RPCAddr != "10.0.0.1:9999" {
		t.Fatalf("RPCAddr should stay '10.0.0.1:9999', got %q", cfg.RPCAddr)
	}
	if cfg.AgentName != "CustomAgent" {
		t.Fatalf("AgentName should stay 'CustomAgent', got %q", cfg.AgentName)
	}
	if cfg.AgentVersion != "1.0.0" {
		t.Fatalf("AgentVersion should stay '1.0.0', got %q", cfg.AgentVersion)
	}
	if cfg.BaseMTU != 1500 {
		t.Fatalf("BaseMTU should stay 1500, got %d", cfg.BaseMTU)
	}
}

func TestNewClientConfigSetsForcedDefaults(t *testing.T) {
	// InsecureSkipVerify and CiscoCompat are always forced.
	cfg := &ClientConfig{
		InsecureSkipVerify: true,
		CiscoCompat:        false,
	}
	ApplyDefaults(cfg)

	if cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should be forced to false")
	}
	if !cfg.CiscoCompat {
		t.Fatal("CiscoCompat should be forced to true")
	}
}

func TestNewInterfaceReturnsEmpty(t *testing.T) {
	iface := NewInterface()
	if iface.Name != "" || iface.Ip4 != "" || iface.Mac != "" || iface.Gateway != "" {
		t.Fatalf("expected empty Interface, got %+v", iface)
	}
}

func TestSetupNilHandling(t *testing.T) {
	// Setup with nil config should not panic; it creates a default internally.
	Setup(nil)
}
