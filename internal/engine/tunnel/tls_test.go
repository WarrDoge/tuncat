package tunnel

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.uber.org/atomic"

	"github.com/WarrDoge/tuncat/internal/engine/protocol"
	enginesession "github.com/WarrDoge/tuncat/internal/engine/session"
)

// TestTlsFragmentaryReadsNoPanic verifies that when bufR.Read returns fewer
// than 8 bytes on the first call, tlsChannel logs an error and returns
// cleanly instead of panicking with an index-out-of-range.
func TestTlsFragmentaryReadsNoPanic(t *testing.T) {
	cert, err := genTestCert()
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	clientCfg := &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}

	// Start a TCP listener and accept one connection.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	// Accept the server-side TLS connection and write 4 bytes.
	go func() {
		defer close(done)
		srv, err := ln.Accept()
		if err != nil {
			return
		}
		srv.Write([]byte{0x53, 0x54, 0x46, 0x01}) // 4 bytes of a CSTP header
		srv.Close()
	}()

	cli, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatal(err)
	}

	bufR := bufio.NewReaderSize(cli, 128)

	sess := &enginesession.Session{
		CloseChan:   make(chan struct{}),
		ActiveClose: false,
	}
	cSess := &enginesession.ConnSession{
		Sess:              sess,
		CloseChan:         make(chan struct{}),
		PayloadIn:         make(chan *protocol.Payload, 64),
		PayloadOutTLS:     make(chan *protocol.Payload, 64),
		PayloadOutDTLS:    make(chan *protocol.Payload, 64),
		ResetTLSReadDead:  atomic.NewBool(false),
		DtlsConnected:     atomic.NewBool(false),
	}
	sess.CSess = cSess

	resp := &http.Response{Body: io.NopCloser(strings.NewReader(""))}

	result := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				result <- r.(error)
			}
		}()
		tlsChannel(cli, bufR, cSess, resp)
		result <- nil
	}()

	select {
	case err := <-result:
		if err != nil {
			t.Fatal("tlsChannel panicked:", err)
		}
		// Success: clean return without panic.
	case <-time.After(2 * time.Second):
		t.Fatal("tlsChannel did not return within timeout")
	}
	<-done
}

func genTestCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}
