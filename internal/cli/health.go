package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// ConnectionState represents the current VPN connection phase.
type ConnectionState string

const (
	StateDisconnected ConnectionState = "disconnected"
	StateConnecting   ConnectionState = "connecting"
	StateConnected    ConnectionState = "connected"
	StateReconnecting ConnectionState = "reconnecting"
)

// HealthSnapshot is the JSON payload served by the health socket.
type HealthSnapshot struct {
	State            ConnectionState `json:"state"`
	UptimeSeconds    int64           `json:"uptime_seconds"`
	BytesSent        uint64          `json:"bytes_sent"`
	BytesReceived    uint64          `json:"bytes_received"`
	ConnectedSince   *time.Time      `json:"connected_since,omitempty"`
	ServerAddress    string          `json:"server_address,omitempty"`
	LocalAddress     string          `json:"local_address,omitempty"`
	ClientIP         string          `json:"client_ip,omitempty"`
}

// HealthTracker accumulates live state that the health endpoint serves.
// All fields are safe to read/write from different goroutines.
type HealthTracker struct {
	state          atomic.Value // ConnectionState
	connectedSince atomic.Value // *time.Time
	bytesSent      atomic.Uint64
	bytesReceived  atomic.Uint64
	serverAddress  atomic.Value // string
	localAddress   atomic.Value // string
	clientIP       atomic.Value // string
}

// NewHealthTracker creates a tracker starting in the disconnected state.
func NewHealthTracker() *HealthTracker {
	ht := &HealthTracker{}
	ht.state.Store(StateDisconnected)
	ht.connectedSince.Store((*time.Time)(nil))
	ht.serverAddress.Store("")
	ht.localAddress.Store("")
	ht.clientIP.Store("")
	return ht
}

// SetDisconnected resets state to disconnected and clears session info.
func (ht *HealthTracker) SetDisconnected() {
	ht.state.Store(StateDisconnected)
	ht.connectedSince.Store((*time.Time)(nil))
}

// SetConnecting marks the state as connecting.
func (ht *HealthTracker) SetConnecting() {
	ht.state.Store(StateConnecting)
}

// SetConnected marks the state as connected and records the connection time.
func (ht *HealthTracker) SetConnected(serverAddr, localAddr, clientIP string) {
	ht.state.Store(StateConnected)
	now := time.Now()
	ht.connectedSince.Store(&now)
	ht.serverAddress.Store(serverAddr)
	ht.localAddress.Store(localAddr)
	ht.clientIP.Store(clientIP)
}

// AddBytes increments the byte counters.
func (ht *HealthTracker) AddBytes(sent, received uint64) {
	ht.bytesSent.Add(sent)
	ht.bytesReceived.Add(received)
}

// SetBytes is used to atomically set the counters from a session read.
func (ht *HealthTracker) SetBytes(sent, received uint64) {
	ht.bytesSent.Store(sent)
	ht.bytesReceived.Store(received)
}

// Snapshot reads all state atomically and returns a consistent snapshot.
func (ht *HealthTracker) Snapshot() HealthSnapshot {
	s := HealthSnapshot{
		State:         ht.state.Load().(ConnectionState),
		BytesSent:     ht.bytesSent.Load(),
		BytesReceived: ht.bytesReceived.Load(),
	}
	if cs := ht.connectedSince.Load(); cs != nil {
		if t, ok := cs.(*time.Time); ok && t != nil {
			s.ConnectedSince = t
			s.UptimeSeconds = int64(time.Since(*t).Seconds())
		}
	}
	if v := ht.serverAddress.Load(); v != nil {
		s.ServerAddress, _ = v.(string)
	}
	if v := ht.localAddress.Load(); v != nil {
		s.LocalAddress, _ = v.(string)
	}
	if v := ht.clientIP.Load(); v != nil {
		s.ClientIP, _ = v.(string)
	}
	return s
}

// ServeHealthSocket listens on a Unix domain socket and serves JSON health
// snapshots until ctx is cancelled. Returns an error channel so the caller
// can react to listen failures immediately.
func ServeHealthSocket(ctx context.Context, socketPath string, tracker *HealthTracker) error {
	// Remove any leftover socket from a previous run.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket %s: %w", socketPath, err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socketPath, err)
	}

	// Restrict permissions to owner-only.
	if err := os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		return fmt.Errorf("chmod %s: %w", socketPath, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tracker.Snapshot())
	})

	srv := &http.Server{
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// logListenerError is a convenience wrapper; it always returns nil so callers
// can use it in a goroutine that is expected to run for the process lifetime.
func logListenerError(err error) {
	if err != nil {
		log.Printf("health socket error: %v", err)
	}
}
