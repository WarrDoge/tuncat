package control

import (
	"context"
	"net/http"
	"testing"

	"github.com/WarrDoge/tuncat/internal/engine"
)

func TestIsLoopbackHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"127.0.0.2", true},
		{"0:0:0:0:0:0:0:1", true},
		{"vpn.example.com", false},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"", false},
		{"  localhost  ", true},
		{"[::1]", true},
	}

	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			if got := isLoopbackHost(tc.host); got != tc.want {
				t.Fatalf("isLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestNormalizeRPCAddr(t *testing.T) {
	tests := []struct {
		addr    string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"  ", "", false},
		{"6210", "127.0.0.1:6210", false},
		{":6210", "127.0.0.1:6210", false},
		{"127.0.0.1:6210", "127.0.0.1:6210", false},
		{"localhost:6210", "localhost:6210", false},
		{"[::1]:6210", "[::1]:6210", false},
		{"0.0.0.0:6210", "", true},
		{"vpn.example.com:6210", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			got, err := normalizeRPCAddr(tc.addr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeRPCAddr(%q) should return error, got %q", tc.addr, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeRPCAddr(%q) = error: %v", tc.addr, err)
			}
			if got != tc.want {
				t.Fatalf("normalizeRPCAddr(%q) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

func TestIsAllowedRPCOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{"no origin", "", true},
		{"localhost origin", "http://localhost:3000", true},
		{"loopback ipv4", "http://127.0.0.1:8080", true},
		{"loopback ipv6", "http://[::1]:8080", true},
		{"external origin", "http://evil.com", false},
		{"external ip", "http://192.168.1.1", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/rpc", nil)
			req.Header.Set("Origin", tc.origin)
			if got := isAllowedRPCOrigin(req); got != tc.want {
				t.Fatalf("isAllowedRPCOrigin(origin=%q) = %v, want %v", tc.origin, got, tc.want)
			}
		})
	}
}

func TestNewRPCServerWithNilCtx(t *testing.T) {
	server := NewRPCServer(nil)
	if server == nil {
		t.Fatal("NewRPCServer(nil) should return non-nil server")
	}
	if server.ctx == nil {
		t.Fatal("NewRPCServer(nil) should create a new context")
	}
	if server.disconnectedStr != "disconnected" {
		t.Fatalf("disconnectedStr = %q, want %q", server.disconnectedStr, "disconnected")
	}
}

func TestRPCServerContext(t *testing.T) {
	ctx := engine.NewContext()
	server := NewRPCServer(ctx)
	if server.Context() != ctx {
		t.Fatal("Context() should return the same context")
	}
}

func TestRPCServerSetupNormalizesAddr(t *testing.T) {
	// Setup should succeed with a bare port (will normalize to 127.0.0.1:port).
	// We use port 0 to avoid conflicts, but the http.Server will fail to listen
	// on that. The actual run happens in a goroutine and errors are logged.
	// So we test a case where addr is empty (should return nil immediately).
	ctx := engine.NewContext()
	server := NewRPCServer(ctx)
	server.ctx.Cfg.RPCAddr = ""
	if err := server.Setup(); err != nil {
		t.Fatalf("Setup with empty addr should succeed: %v", err)
	}
}

func TestRPCServerShutdownNoServer(t *testing.T) {
	server := NewRPCServer(engine.NewContext())
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown without Setup should succeed: %v", err)
	}
}
