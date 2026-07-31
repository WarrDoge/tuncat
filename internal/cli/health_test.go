package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHealthTrackerInitialState(t *testing.T) {
	ht := NewHealthTracker()
	snap := ht.Snapshot()
	if snap.State != StateDisconnected {
		t.Fatalf("initial state = %q, want %q", snap.State, StateDisconnected)
	}
	if snap.UptimeSeconds != 0 {
		t.Fatalf("initial uptime = %d, want 0", snap.UptimeSeconds)
	}
	if snap.BytesSent != 0 || snap.BytesReceived != 0 {
		t.Fatalf("initial bytes = (%d, %d), want (0, 0)", snap.BytesSent, snap.BytesReceived)
	}
	if snap.ConnectedSince != nil {
		t.Fatalf("initial connected_since = %v, want nil", snap.ConnectedSince)
	}
}

func TestHealthTrackerConnected(t *testing.T) {
	ht := NewHealthTracker()
	ht.SetConnected("vpn.example.com:443", "192.168.1.5:0", "10.0.0.2")

	snap := ht.Snapshot()
	if snap.State != StateConnected {
		t.Fatalf("state = %q, want %q", snap.State, StateConnected)
	}
	if snap.ServerAddress != "vpn.example.com:443" {
		t.Fatalf("server_address = %q, want %q", snap.ServerAddress, "vpn.example.com:443")
	}
	if snap.LocalAddress != "192.168.1.5:0" {
		t.Fatalf("local_address = %q, want %q", snap.LocalAddress, "192.168.1.5:0")
	}
	if snap.ClientIP != "10.0.0.2" {
		t.Fatalf("client_ip = %q, want %q", snap.ClientIP, "10.0.0.2")
	}
	if snap.ConnectedSince == nil {
		t.Fatal("connected_since is nil, want non-nil")
	}
	if snap.UptimeSeconds < 0 {
		t.Fatalf("uptime_seconds = %d, want >= 0", snap.UptimeSeconds)
	}
}

func TestHealthTrackerConnecting(t *testing.T) {
	ht := NewHealthTracker()
	ht.SetConnecting()

	snap := ht.Snapshot()
	if snap.State != StateConnecting {
		t.Fatalf("state = %q, want %q", snap.State, StateConnecting)
	}
	if snap.ConnectedSince != nil {
		t.Fatalf("connected_since = %v, want nil during connecting phase", snap.ConnectedSince)
	}
}

func TestHealthTrackerDisconnected(t *testing.T) {
	ht := NewHealthTracker()
	ht.SetConnected("vpn.example.com:443", "192.168.1.5:0", "10.0.0.2")
	ht.AddBytes(100, 200)
	ht.SetDisconnected()

	snap := ht.Snapshot()
	if snap.State != StateDisconnected {
		t.Fatalf("state after disconnect = %q, want %q", snap.State, StateDisconnected)
	}
	if snap.ConnectedSince != nil {
		t.Fatalf("connected_since after disconnect = %v, want nil", snap.ConnectedSince)
	}
	// Byte counters survive disconnect — they are session totals.
	if snap.BytesSent == 0 && snap.BytesReceived == 0 {
		t.Fatal("byte counters were zeroed on disconnect")
	}
}

func TestHealthTrackerBytes(t *testing.T) {
	ht := NewHealthTracker()
	ht.AddBytes(100, 200)
	ht.AddBytes(50, 75)

	snap := ht.Snapshot()
	if snap.BytesSent != 150 {
		t.Fatalf("bytes_sent = %d, want 150", snap.BytesSent)
	}
	if snap.BytesReceived != 275 {
		t.Fatalf("bytes_received = %d, want 275", snap.BytesReceived)
	}
}

func TestHealthTrackerSetBytes(t *testing.T) {
	ht := NewHealthTracker()
	ht.AddBytes(100, 200)
	ht.SetBytes(500, 600)

	snap := ht.Snapshot()
	if snap.BytesSent != 500 {
		t.Fatalf("bytes_sent = %d, want 500", snap.BytesSent)
	}
	if snap.BytesReceived != 600 {
		t.Fatalf("bytes_received = %d, want 600", snap.BytesReceived)
	}
}

func TestHealthSocketQuery(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "tuncat.sock")
	ht := NewHealthTracker()
	ht.SetConnected("vpn.example.com:443", "192.168.1.5:0", "10.0.0.2")
	ht.AddBytes(1024, 2048)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeHealthSocket(ctx, socketPath, ht)
	}()

	// Wait for the socket to exist.
	var dialErr error
	for i := 0; i < 50; i++ {
		_, dialErr = os.Stat(socketPath)
		if dialErr == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if dialErr != nil {
		t.Fatalf("socket did not appear: %v", dialErr)
	}

	// Query the socket with a raw connection.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	var resp *http.Response
	br := bufio.NewReader(conn)
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var snap HealthSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	resp.Body.Close()

	if snap.State != StateConnected {
		t.Fatalf("state = %q, want %q", snap.State, StateConnected)
	}
	if snap.ServerAddress != "vpn.example.com:443" {
		t.Fatalf("server_address = %q", snap.ServerAddress)
	}
	if snap.BytesSent != 1024 || snap.BytesReceived != 2048 {
		t.Fatalf("bytes = (%d, %d), want (1024, 2048)", snap.BytesSent, snap.BytesReceived)
	}
}

func TestHealthSocketRejectsPost(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "tuncat-reject.sock")
	ht := NewHealthTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = ServeHealthSocket(ctx, socketPath, ht)
	}()

	// Wait for the socket.
	var dialErr error
	for i := 0; i < 50; i++ {
		_, dialErr = os.Stat(socketPath)
		if dialErr == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if dialErr != nil {
		t.Fatalf("socket did not appear: %v", dialErr)
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "POST /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	var resp *http.Response
	br := bufio.NewReader(conn)
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestHealthSocketStaleSocketReplaced(t *testing.T) {
	tmp := t.TempDir()
	socketPath := filepath.Join(tmp, "tuncat.sock")

	// Create a stale socket file.
	if err := os.WriteFile(socketPath, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}

	ht := NewHealthTracker()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeHealthSocket(ctx, socketPath, ht)
	}()

	// Dial the socket to confirm it's alive — this also proves the stale
	// file was replaced since net.Listen would fail otherwise.
	var dialErr error
	for i := 0; i < 50; i++ {
		conn, dialErr := net.Dial("unix", socketPath)
		if dialErr == nil {
			conn.Close()
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if dialErr != nil {
		t.Fatalf("could not dial socket: %v (ServeHealthSocket error: %v)", dialErr, <-errCh)
	}
}

func TestHealthTrackerJSONMarshal(t *testing.T) {
	ht := NewHealthTracker()
	ht.SetConnected("srv:443", "127.0.0.1:0", "10.0.0.2")
	ht.AddBytes(1, 2)

	snap := ht.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded HealthSnapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.State != StateConnected {
		t.Fatalf("state = %q", decoded.State)
	}
	if decoded.BytesSent != 1 || decoded.BytesReceived != 2 {
		t.Fatalf("bytes = (%d, %d)", decoded.BytesSent, decoded.BytesReceived)
	}
	if decoded.ServerAddress != "srv:443" {
		t.Fatalf("server_address = %q", decoded.ServerAddress)
	}
	if decoded.ConnectedSince == nil {
		t.Fatal("connected_since is nil")
	}
}
