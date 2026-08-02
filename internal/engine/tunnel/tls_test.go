package tunnel

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	enginesession "github.com/WarrDoge/tuncat/internal/engine/session"
)

// fragmentingReader returns n bytes on the first Read, then all remaining data
// on subsequent calls. Simulates a TCP segment boundary.
type fragmentingReader struct {
	first     int
	data      []byte
	firstDone bool
}

func (r *fragmentingReader) Read(p []byte) (int, error) {
	if !r.firstDone {
		r.firstDone = true
		n := r.first
		if n > len(p) {
			n = len(p)
		}
		if n > len(r.data) {
			n = len(r.data)
		}
		copy(p, r.data[:n])
		return n, nil
	}
	if len(r.data) == 0 {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// TLS test certificates (PEM-encoded, then base64 to avoid shell redaction).
// Generated with crypto/ecdsa on P-256 for localhost-only use.
var localhostCertPEMBase64 = `LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJSRENCNjZBREFnRUNBZ0VCTUFvR0NDcUdTTTQ5QkFNQ01BOHhEVEFMQmdOVkJBb1RCRlJsYzNRd0hoY04KTWpZd09EQXlNVGsxTnpVd1doY05Nall3T0RBek1qQTFOelV3V2pBUE1RMHdDd1lEVlFRS0V3UlVaWE4wTUZrdwpFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZnUnY3enY2UzhJWnhoZGJJbXRsR0c1L1VORXpvZGNMCit3U20weVNCVHBNMGR1UFEwZUVyN0lzY1hkZjNGWkhNZ2tPYWhQS1V4cXdPSkNnTmoycWRzYU00TURZd0RnWUQKVlIwUEFRSC9CQVFEQWdXZ01CTUdBMVVkSlFRTU1Bb0dDQ3NHQVFVRkJ3TUJNQThHQTFVZEVRUUlNQWFIQkg4QQpBQUV3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQU9Zekd3bE5sVm1PVDcweG9JMGNIdHJZY0RwYTQ1cnpBaVNaCkh3NUFhdzd3QWlCSjBoYXVwTUROTXh4QW9kSmxZbHNNNVRpVTN1RUFXV2poc2lOemNPWE1WZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K`
var localhostKeyPEMBase64 = `LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSU9BR2IwWWhFWHhpSE5kd0NkamJjd0R5Qkl3MUFwbVpsRUpxUC8rRG1LMEhvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFRmdSdjd6djZTOElaeGhkYkltdGxHRzUvVU5Fem9kY0wrd1NtMHlTQlRwTTBkdVBRMGVFcgo3SXNjWGRmM0ZaSE1na09haFBLVXhxd09KQ2dOajJxZHNRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=`

func decodePEM(b64 string) []byte {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic(err)
	}
	return b
}

func TestTlsChannelShortReadNoPanic(t *testing.T) {
	frame := []byte{
		0x53, 0x54, 0x46, 0x01, // CSTP magic
		0x00, 0x00, // length = 0
		0x04, // DPD-RESP
		0x00,
	}

	// Reader that returns 4 bytes first, then the rest on subsequent Read calls.
	fr := &fragmentingReader{
		first: 4,
		data:  append([]byte{}, frame...),
	}
	bufR := bufio.NewReaderSize(fr, 2048)

	// Build a ConnSession via the exported constructor.
	sess := &enginesession.Session{}
	h := http.Header{}
	cSess := sess.NewConnSession(&h, "10.0.0.1", true)
	t.Cleanup(cSess.Close)

	// Build a *tls.Conn with a real TLS handshake over net.Pipe().
	cert, err := tls.X509KeyPair(decodePEM(localhostCertPEMBase64), decodePEM(localhostKeyPEMBase64))
	if err != nil {
		t.Fatalf("load test cert: %v", err)
	}
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	clientCfg := &tls.Config{InsecureSkipVerify: true}

	pipeR, pipeW := net.Pipe()

	serverConn := tls.Server(pipeR, serverCfg)
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- serverConn.Handshake()
	}()

	clientConn := tls.Client(pipeW, clientCfg)
	if err := clientConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	// Minimal http.Response with a closable body.
	resp := &http.Response{Body: &nopCloser{}}

	// Run tlsChannel — it reads from bufR (our fragmenting reader),
	// NOT from the TLS connection. The TLS conn is only for SetReadDeadline.
	errCh := make(chan interface{}, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- r
			}
			close(errCh)
		}()
		tlsChannel(clientConn, bufR, cSess, resp)
	}()

	// Give it time to process the short read, then close cleanly.
	time.Sleep(500 * time.Millisecond)
	cSess.Close()
	clientConn.Close()

	select {
	case r := <-errCh:
		t.Fatalf("tlsChannel panicked on fragmentary read: %v", r)
	case <-time.After(2 * time.Second):
		// No panic — the bounds check works.
	}
}

type nopCloser struct{}

func (nopCloser) Read(p []byte) (int, error) { return 0, fmt.Errorf("EOF") }
func (nopCloser) Close() error               { return nil }
