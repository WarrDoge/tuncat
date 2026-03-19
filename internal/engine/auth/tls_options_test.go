package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func newTestConnectionState(t *testing.T) tls.ConnectionState {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
}

func TestVerifyServerCertPinFormats(t *testing.T) {
	state := newTestConnectionState(t)
	leaf := state.PeerCertificates[0]

	sha256Sum := sha256.Sum256(leaf.Raw)
	sha1Sum := sha1.Sum(leaf.Raw)
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)

	tests := []string{
		"sha256:" + hex.EncodeToString(sha256Sum[:]),
		"sha1:" + hex.EncodeToString(sha1Sum[:]),
		"pin-sha256:" + base64.StdEncoding.EncodeToString(spki[:]),
	}

	for _, pin := range tests {
		if err := verifyServerCertPin(pin, state); err != nil {
			t.Fatalf("verifyServerCertPin(%q) error: %v", pin, err)
		}
	}
}

func TestVerifyServerCertPinMismatch(t *testing.T) {
	state := newTestConnectionState(t)
	if err := verifyServerCertPin("sha256:"+strings.Repeat("00", 32), state); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestVerifyServerCertPinUnsupportedFormat(t *testing.T) {
	state := newTestConnectionState(t)
	if err := verifyServerCertPin("md5:deadbeef", state); err == nil {
		t.Fatal("expected unsupported format error")
	}
}

func TestVerifyServerCertPinNoPeerCert(t *testing.T) {
	if err := verifyServerCertPin("sha256:00", tls.ConnectionState{}); err == nil {
		t.Fatal("expected no peer certificate error")
	}
}

func TestDecodeHexFingerprint(t *testing.T) {
	decoded, err := decodeHexFingerprint("AA:bb:01")
	if err != nil {
		t.Fatalf("decodeHexFingerprint error: %v", err)
	}
	if hex.EncodeToString(decoded) != "aabb01" {
		t.Fatalf("decoded fingerprint = %q, want %q", hex.EncodeToString(decoded), "aabb01")
	}

	if _, err := decodeHexFingerprint("zz"); err == nil {
		t.Fatal("expected invalid fingerprint error")
	}
}
