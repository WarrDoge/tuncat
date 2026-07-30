package control

import (
	"testing"

	"github.com/WarrDoge/tuncat/internal/engine"
	engineconfig "github.com/WarrDoge/tuncat/internal/engine/config"
	enginesession "github.com/WarrDoge/tuncat/internal/engine/session"
)

func TestEnsureContextNil(t *testing.T) {
	err := ensureContext(nil)
	if err == nil {
		t.Fatal("ensureContext(nil) should return error")
	}
}

func TestEnsureContextEmpty(t *testing.T) {
	ctx := &engine.Context{}
	if err := ensureContext(ctx); err != nil {
		t.Fatalf("ensureContext(empty ctx) returned error: %v", err)
	}
	if ctx.Cfg == nil {
		t.Fatal("ensureContext should populate Cfg")
	}
	if ctx.LocalInterface == nil {
		t.Fatal("ensureContext should populate LocalInterface")
	}
	if ctx.Profile == nil {
		t.Fatal("ensureContext should populate Profile")
	}
	if ctx.Session == nil {
		t.Fatal("ensureContext should populate Session")
	}
	if ctx.Auth == nil {
		t.Fatal("ensureContext should populate Auth")
	}
	if ctx.Logger == nil {
		t.Fatal("ensureContext should populate Logger")
	}
}

func TestEnsureContextPreservesExisting(t *testing.T) {
	cfg := engineconfig.NewClientConfig()
	cfg.LogLevel = "Error"
	profile := engine.NewProfile()
	profile.Host = "vpn.example.com"
	sess := &enginesession.Session{}
	sess.SessionToken = "tok-123"

	ctx := &engine.Context{
		Cfg:     cfg,
		Profile: profile,
		Session: sess,
	}
	if err := ensureContext(ctx); err != nil {
		t.Fatalf("ensureContext should succeed: %v", err)
	}
	if ctx.Cfg.LogLevel != "Error" {
		t.Fatal("ensureContext should not overwrite existing Cfg")
	}
	if ctx.Profile.Host != "vpn.example.com" {
		t.Fatal("ensureContext should not overwrite existing Profile")
	}
	if ctx.Session.SessionToken != "tok-123" {
		t.Fatal("ensureContext should not overwrite existing Session")
	}
}

func TestConnectNilCtx(t *testing.T) {
	if err := Connect(nil); err == nil {
		t.Fatal("Connect(nil) should return error")
	}
}

func TestSetupTunnelNilCtx(t *testing.T) {
	if err := SetupTunnel(false, nil); err == nil {
		t.Fatal("SetupTunnel(false, nil) should return error")
	}
	if err := SetupTunnel(true, nil); err == nil {
		t.Fatal("SetupTunnel(true, nil) should return error")
	}
}

func TestDisConnectNilCtx(t *testing.T) {
	// DisConnect should not panic on nil context.
	DisConnect(nil)
}

func TestDisConnectEmptyCtx(t *testing.T) {
	// DisConnect with a newly-created context should not panic.
	ctx := &engine.Context{}
	DisConnect(ctx)
}
