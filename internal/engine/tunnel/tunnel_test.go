package tunnel

import (
	"encoding/hex"
	"testing"

	"github.com/pion/dtls/v3"
	"github.com/WarrDoge/tuncat/internal/engine"
)

func TestInitTunnelDefaultMTU(t *testing.T) {
	ctx := engine.NewContext()
	ctx.Cfg.BaseMTU = 0 // triggers default of 1200

	headers := initTunnel(ctx)

	if mtu := headers["X-CSTP-MTU"]; mtu != "1200" {
		t.Fatalf("X-CSTP-MTU = %q, want 1200", mtu)
	}
	if base := headers["X-CSTP-Base-MTU"]; base != "1200" {
		t.Fatalf("X-CSTP-Base-MTU = %q, want 1200", base)
	}
}

func TestInitTunnelCustomMTU(t *testing.T) {
	ctx := engine.NewContext()
	ctx.Cfg.BaseMTU = 1400

	headers := initTunnel(ctx)

	if mtu := headers["X-CSTP-MTU"]; mtu != "1400" {
		t.Fatalf("X-CSTP-MTU = %q, want 1400", mtu)
	}
}

func TestInitTunnelIncludesSessionToken(t *testing.T) {
	ctx := engine.NewContext()
	ctx.Session.SessionToken = "tok_abc123"

	headers := initTunnel(ctx)

	if cookie := headers["Cookie"]; cookie != "webvpn=tok_abc123" {
		t.Fatalf("Cookie = %q, want webvpn=tok_abc123", cookie)
	}
}

func TestInitTunnelIncludesLocalIP(t *testing.T) {
	ctx := engine.NewContext()
	ctx.LocalInterface.Ip4 = "10.0.0.5"

	headers := initTunnel(ctx)

	if ip := headers["X-CSTP-Local-VPNAddress-IP4"]; ip != "10.0.0.5" {
		t.Fatalf("X-CSTP-Local-VPNAddress-IP4 = %q, want 10.0.0.5", ip)
	}
}

func TestInitTunnelSetsPreMasterSecretAndDTLSHeader(t *testing.T) {
	ctx := engine.NewContext()
	ctx.Session.SessionToken = "tok"

	headers := initTunnel(ctx)

	// PreMasterSecret was set on the session.
	if len(ctx.Session.PreMasterSecret) != 48 {
		t.Fatalf("PreMasterSecret length = %d, want 48", len(ctx.Session.PreMasterSecret))
	}

	// DTLS master secret header is hex of the secret.
	expectedHex := hex.EncodeToString(ctx.Session.PreMasterSecret)
	if secret := headers["X-DTLS-Master-Secret"]; secret != expectedHex {
		t.Fatalf("X-DTLS-Master-Secret = %q, want %q", secret, expectedHex)
	}
}

func TestInitTunnelDTLSCipherSuite(t *testing.T) {
	ctx := engine.NewContext()
	ctx.Session.SessionToken = "tok"

	headers := initTunnel(ctx)

	expected := "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256"
	if suite := headers["X-DTLS12-CipherSuite"]; suite != expected {
		t.Fatalf("X-DTLS12-CipherSuite = %q, want %q", suite, expected)
	}
}

func TestInitTunnelVPNAddressType(t *testing.T) {
	ctx := engine.NewContext()
	ctx.Session.SessionToken = "tok"
	ctx.LocalInterface.Ip4 = "192.168.1.10"

	headers := initTunnel(ctx)

	if v := headers["X-CSTP-VPNAddress-Type"]; v != "IPv4" {
		t.Fatalf("X-CSTP-VPNAddress-Type = %q, want IPv4", v)
	}
}

func TestSessionStoreGetSet(t *testing.T) {
	id := []byte{0x01, 0x02, 0x03}
	expectedSess := dtls.Session{ID: id, Secret: []byte("secret")}

	store := &SessionStore{sess: expectedSess}

	got, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if string(got.Secret) != "secret" {
		t.Fatalf("session secret = %q, want %q", string(got.Secret), "secret")
	}
}

func TestSessionStoreSetReturnsNil(t *testing.T) {
	store := &SessionStore{}
	if err := store.Set([]byte{0x01}, dtls.Session{}); err != nil {
		t.Fatalf("Set error: %v", err)
	}
}

func TestSessionStoreDelReturnsNil(t *testing.T) {
	store := &SessionStore{}
	if err := store.Del([]byte{0x01}); err != nil {
		t.Fatalf("Del error: %v", err)
	}
}

func TestSetupTunnelNilContext(t *testing.T) {
	err := SetupTunnel(nil)
	if err == nil {
		t.Fatal("expected error for nil context")
	}
	if err.Error() != "vpn context is nil" {
		t.Fatalf("error = %q, want %q", err.Error(), "vpn context is nil")
	}
}

func TestSetupTunnelIncompleteContext(t *testing.T) {
	ctx := engine.NewContext()
	ctx.Cfg = nil
	err := SetupTunnel(ctx)
	if err == nil {
		t.Fatal("expected error for incomplete context")
	}
	if err.Error() != "vpn context is incomplete" {
		t.Fatalf("error = %q, want %q", err.Error(), "vpn context is incomplete")
	}
}

func TestSetupTunnelNilAuth(t *testing.T) {
	ctx := engine.NewContext()
	ctx.Auth = nil
	err := SetupTunnel(ctx)
	if err == nil {
		t.Fatal("expected error for nil auth")
	}
}

func TestSetupTunnelAuthNotInitialized(t *testing.T) {
	ctx := engine.NewContext()
	// Auth exists but Conn is nil.
	err := SetupTunnel(ctx)
	if err == nil {
		t.Fatal("expected error for uninitialized auth transport")
	}
	if err.Error() != "auth transport is not initialized" {
		t.Fatalf("error = %q, want %q", err.Error(), "auth transport is not initialized")
	}
}
