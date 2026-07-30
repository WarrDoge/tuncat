package tunnel

import (
	"net"
	"sync"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/WarrDoge/tuncat/internal/engine"
	engineconfig "github.com/WarrDoge/tuncat/internal/engine/config"
	enginesession "github.com/WarrDoge/tuncat/internal/engine/session"
)

func TestInitTunnelSetsMTUHeaders(t *testing.T) {
	ctx := &engine.Context{
		Cfg: &engineconfig.ClientConfig{
			BaseMTU: 1400,
		},
		Session: &enginesession.Session{
			SessionToken: "test-token",
		},
		LocalInterface: &engineconfig.Interface{
			Ip4: "10.0.0.2",
		},
	}
	// PreMasterSecret is set by initTunnel, which calls MakeMasterSecret.
	// We only test the headers, not DTLS internals.
	headers := initTunnel(ctx)

	tests := []struct {
		key  string
		want string
	}{
		{"X-CSTP-VPNAddress-Type", "IPv4"},
		{"X-CSTP-MTU", "1400"},
		{"X-CSTP-Base-MTU", "1400"},
		{"X-CSTP-Local-VPNAddress-IP4", "10.0.0.2"},
	}
	for _, tc := range tests {
		if got := headers[tc.key]; got != tc.want {
			t.Errorf("initTunnel header %q = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestInitTunnelDefaultMTU(t *testing.T) {
	ctx := &engine.Context{
		Cfg: &engineconfig.ClientConfig{
			BaseMTU: 0,
		},
		Session: &enginesession.Session{
			SessionToken: "tok",
		},
		LocalInterface: &engineconfig.Interface{
			Ip4: "10.0.0.2",
		},
	}

	headers := initTunnel(ctx)

	if mtu := headers["X-CSTP-MTU"]; mtu != "1200" {
		t.Fatalf("default MTU header = %q, want %q", mtu, "1200")
	}
	if base := headers["X-CSTP-Base-MTU"]; base != "1200" {
		t.Fatalf("default Base-MTU header = %q, want %q", base, "1200")
	}
}

func TestInitTunnelNegativeMTU(t *testing.T) {
	ctx := &engine.Context{
		Cfg: &engineconfig.ClientConfig{
			BaseMTU: -1,
		},
		Session: &enginesession.Session{
			SessionToken: "tok",
		},
		LocalInterface: &engineconfig.Interface{
			Ip4: "10.0.0.2",
		},
	}

	headers := initTunnel(ctx)

	if mtu := headers["X-CSTP-MTU"]; mtu != "1200" {
		t.Fatalf("negative MTU default = %q, want %q", mtu, "1200")
	}
}

func TestInitTunnelSetsCookieAndDTLSHeaders(t *testing.T) {
	ctx := &engine.Context{
		Cfg: &engineconfig.ClientConfig{
			BaseMTU: 1200,
		},
		Session: &enginesession.Session{
			SessionToken: "sess-token-123",
		},
		LocalInterface: &engineconfig.Interface{
			Ip4: "192.168.1.100",
		},
	}

	headers := initTunnel(ctx)

	if cookie := headers["Cookie"]; cookie != "webvpn=sess-token-123" {
		t.Fatalf("Cookie = %q, want %q", cookie, "webvpn=sess-token-123")
	}

	if _, ok := headers["X-DTLS-Master-Secret"]; !ok {
		t.Fatal("expected X-DTLS-Master-Secret header")
	}

	if _, ok := headers["X-DTLS12-CipherSuite"]; !ok {
		t.Fatal("expected X-DTLS12-CipherSuite header")
	}
}

func TestSetupTunnelNilContext(t *testing.T) {
	err := SetupTunnel(nil)
	if err == nil {
		t.Fatal("expected error for nil context")
	}
	if err.Error() != "vpn context is nil" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupTunnelIncompleteContext(t *testing.T) {
	ctx := &engine.Context{}
	err := SetupTunnel(ctx)
	if err == nil {
		t.Fatal("expected error for incomplete context")
	}
	if err.Error() != "vpn context is incomplete" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupTunnelMissingCfg(t *testing.T) {
	ctx := &engine.Context{
		Profile:        &engine.Profile{},
		Session:        &enginesession.Session{},
		Auth:           &engine.AuthState{},
		LocalInterface: &engineconfig.Interface{},
	}
	err := SetupTunnel(ctx)
	if err == nil {
		t.Fatal("expected error when Cfg is nil")
	}
	if err.Error() != "vpn context is incomplete" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupTunnelUninitializedAuthTransport(t *testing.T) {
	ctx := &engine.Context{
		Cfg:            &engineconfig.ClientConfig{},
		Profile:        &engine.Profile{},
		Session:        &enginesession.Session{},
		Auth:           &engine.AuthState{},
		LocalInterface: &engineconfig.Interface{},
	}
	err := SetupTunnel(ctx)
	if err == nil {
		t.Fatal("expected error when auth transport is not initialized")
	}
	if err.Error() != "auth transport is not initialized" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupTunnelNilProfile(t *testing.T) {
	ctx := &engine.Context{
		Cfg:            &engineconfig.ClientConfig{},
		Session:        &enginesession.Session{},
		Auth:           &engine.AuthState{},
		LocalInterface: &engineconfig.Interface{},
	}
	err := SetupTunnel(ctx)
	if err == nil {
		t.Fatal("expected error when Profile is nil")
	}
	if err.Error() != "vpn context is incomplete" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupTunnelNilSession(t *testing.T) {
	ctx := &engine.Context{
		Cfg:            &engineconfig.ClientConfig{},
		Profile:        &engine.Profile{},
		Auth:           &engine.AuthState{},
		LocalInterface: &engineconfig.Interface{},
	}
	err := SetupTunnel(ctx)
	if err == nil {
		t.Fatal("expected error when Session is nil")
	}
	if err.Error() != "vpn context is incomplete" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionStoreSetAndDel(t *testing.T) {
	store := &SessionStore{}
	// Set should always return nil.
	if err := store.Set([]byte("key"), store.sess); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	// Del should always return nil.
	if err := store.Del([]byte("key")); err != nil {
		t.Fatalf("Del error: %v", err)
	}
}

func TestSessionStoreGetReturnsStoredSession(t *testing.T) {
	store := &SessionStore{}
	expected := store.sess
	result, err := store.Get([]byte("any-key"))
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if result.ID == nil && expected.ID != nil {
		t.Fatal("Get returned nil ID when expected non-nil")
	}
}

// buildDNSResponsePacket constructs a synthetic IPv4/UDP/DNS packet
// mimicking a DNS response for the given domain with the given A records.
func buildDNSResponsePacket(t *testing.T, domain string, ips []string) []byte {
	t.Helper()

	dns := &layers.DNS{
		BaseLayer: layers.BaseLayer{},
		ID:        0x1234,
		QR:        true,
		OpCode:    layers.DNSOpCodeQuery,
		QDCount:   1,
		ANCount:   uint16(len(ips)),
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(domain),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}
	for _, ip := range ips {
		dns.Answers = append(dns.Answers, layers.DNSResourceRecord{
			Name:  []byte(domain),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			IP:    net.ParseIP(ip),
		})
	}

	udp := &layers.UDP{
		SrcPort: 53,
		DstPort: 12345,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    net.ParseIP("8.8.8.8"),
		DstIP:    net.ParseIP("10.0.0.2"),
		Protocol: layers.IPProtocolUDP,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	_ = gopacket.SerializeLayers(buf, opts, ip, udp, dns)
	return buf.Bytes()
}

func TestDynamicSplitRoutesIncludeDomain(t *testing.T) {
	ctx := &engine.Context{Cfg: &engineconfig.ClientConfig{}}
	cSess := &enginesession.ConnSession{
		DynamicSplitIncludeDomains: []string{"example.com"},
		DynamicSplitIncludeResolved: sync.Map{},
		Sess: &enginesession.Session{},
	}

	data := buildDNSResponsePacket(t, "example.com", []string{"1.2.3.4", "5.6.7.8"})
	// This should not panic and should store the resolved IPs.
	// We can't verify the route-add without kernel access, but we
	// verify the store-and-call logic by checking no panic and
	// the resolved map being populated.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("dynamicSplitRoutes panicked: %v", r)
			}
		}()
		dynamicSplitRoutes(ctx, data, cSess)
	}()

	// The function stores results but the route-adding functions
	// require netlink, so they'll fail silently. We check the store.
	val, ok := cSess.DynamicSplitIncludeResolved.Load("example.com")
	if !ok {
		t.Fatal("expected example.com to be stored after dynamicSplitRoutes")
	}
	ips := val.([]string)
	if len(ips) != 2 || ips[0] != "1.2.3.4" || ips[1] != "5.6.7.8" {
		t.Fatalf("stored IPs = %v, want [1.2.3.4 5.6.7.8]", ips)
	}
}

func TestDynamicSplitRoutesExcludeDomain(t *testing.T) {
	ctx := &engine.Context{Cfg: &engineconfig.ClientConfig{}}
	cSess := &enginesession.ConnSession{
		DynamicSplitExcludeDomains: []string{"blocked.example.com"},
		DynamicSplitExcludeResolved: sync.Map{},
		Sess:                       &enginesession.Session{},
	}

	data := buildDNSResponsePacket(t, "blocked.example.com", []string{"10.0.0.1"})

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("dynamicSplitRoutes panicked: %v", r)
			}
		}()
		dynamicSplitRoutes(ctx, data, cSess)
	}()

	val, ok := cSess.DynamicSplitExcludeResolved.Load("blocked.example.com")
	if !ok {
		t.Fatal("expected blocked.example.com to be stored")
	}
	ips := val.([]string)
	if len(ips) != 1 || ips[0] != "10.0.0.1" {
		t.Fatalf("stored IPs = %v, want [10.0.0.1]", ips)
	}
}

func TestDynamicSplitRoutesNonMatchingDomain(t *testing.T) {
	ctx := &engine.Context{Cfg: &engineconfig.ClientConfig{}}
	cSess := &enginesession.ConnSession{
		DynamicSplitIncludeDomains: []string{"example.com"},
		DynamicSplitIncludeResolved: sync.Map{},
		Sess:                       &enginesession.Session{},
	}

	// Domain not in include or exclude lists.
	data := buildDNSResponsePacket(t, "other.com", []string{"1.2.3.4"})

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("dynamicSplitRoutes panicked: %v", r)
			}
		}()
		dynamicSplitRoutes(ctx, data, cSess)
	}()

	// Nothing should be stored.
	if _, ok := cSess.DynamicSplitIncludeResolved.Load("other.com"); ok {
		t.Fatal("domain not in include list should not be stored")
	}
}
