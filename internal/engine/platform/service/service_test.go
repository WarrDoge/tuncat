package service

import (
	"testing"
)

func TestServiceConfigName(t *testing.T) {
	// The init function sets serviceConfig; verify its fields.
	if serviceConfig == nil {
		t.Fatal("serviceConfig should be initialized by init()")
	}
	expectedName := "tuncat-engine"
	if serviceConfig.Name != expectedName {
		t.Fatalf("Name = %q, want %q", serviceConfig.Name, expectedName)
	}
	if serviceConfig.DisplayName != "Tuncat Engine Service" {
		t.Fatalf("DisplayName = %q, want %q", serviceConfig.DisplayName, "Tuncat Engine Service")
	}
	if serviceConfig.Description != "Tuncat embedded engine service" {
		t.Fatalf("Description = %q, want %q", serviceConfig.Description, "Tuncat embedded engine service")
	}
}

func TestProgramStruct(t *testing.T) {
	if prg == nil {
		t.Fatal("prg should be initialized by init()")
	}
	if prg.server != nil {
		t.Fatal("server should be nil before start")
	}
}
