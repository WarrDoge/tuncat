package session

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func testHeader() http.Header {
	h := http.Header{}
	h.Set("X-CSTP-Address", "10.0.0.10")
	h.Set("X-CSTP-Netmask", "255.255.255.0")
	h.Set("X-CSTP-MTU", "1200")
	h.Add("X-CSTP-DNS", "10.0.0.1")
	h.Add("X-CSTP-Split-Include", "10.0.0.0/255.0.0.0")
	h.Add("X-CSTP-Split-Exclude", "1.1.1.1/255.255.255.255")
	h.Set("X-CSTP-DPD", "15")
	h.Set("X-CSTP-Keepalive", "20")
	h.Set("X-DTLS-Session-ID", "00112233")
	h.Set("X-DTLS-Port", "443")
	h.Set("X-DTLS-DPD", "15")
	h.Set("X-DTLS-Keepalive", "20")
	h.Set("X-DTLS12-CipherSuite", "ECDHE-RSA-AES128-GCM-SHA256")
	h.Set("X-CSTP-Post-Auth-XML", `<config-auth><config><opaque><custom-attr><dynamic-split-include-domains>corp.example.com</dynamic-split-include-domains></custom-attr></opaque></config></config-auth>`)
	return h
}

func newConnSessionForTest(noDTLS bool) (*Session, *ConnSession) {
	sess := &Session{}
	h := testHeader()
	cSess := sess.NewConnSession(&h, "192.0.2.10", noDTLS)
	return sess, cSess
}

func TestNewConnSessionParsesHeaders(t *testing.T) {
	_, cSess := newConnSessionForTest(false)

	if cSess.LocalAddress != "192.0.2.10" {
		t.Fatalf("LocalAddress = %q, want 192.0.2.10", cSess.LocalAddress)
	}
	if cSess.VPNAddress != "10.0.0.10" || cSess.VPNMask != "255.255.255.0" {
		t.Fatalf("VPN address parsing failed: %q/%q", cSess.VPNAddress, cSess.VPNMask)
	}
	if cSess.MTU != 1200 {
		t.Fatalf("MTU = %d, want 1200", cSess.MTU)
	}
	if cSess.DTLSCipherSuite == "" {
		t.Fatal("DTLS cipher suite should be populated")
	}
	if !cSess.DynamicSplitTunneling {
		t.Fatal("DynamicSplitTunneling should be true")
	}
	if len(cSess.DynamicSplitIncludeDomains) != 1 || cSess.DynamicSplitIncludeDomains[0] != "corp.example.com" {
		t.Fatalf("unexpected dynamic split include domains: %v", cSess.DynamicSplitIncludeDomains)
	}
}

func TestNewConnSessionNoDTLS(t *testing.T) {
	_, cSess := newConnSessionForTest(true)
	if cSess.DTLSCipherSuite != "Unknown" {
		t.Fatalf("DTLSCipherSuite = %q, want Unknown", cSess.DTLSCipherSuite)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	sess, cSess := newConnSessionForTest(false)

	cSess.Close()
	cSess.Close()

	if sess.CSess != nil {
		t.Fatal("session connection should be nil after close")
	}

	select {
	case <-cSess.CloseChan:
	default:
		t.Fatal("ConnSession.CloseChan should be closed")
	}

	select {
	case <-sess.CloseChan:
	default:
		t.Fatal("Session.CloseChan should be closed")
	}
}

func TestDPDTimerSendsProbes(t *testing.T) {
	_, cSess := newConnSessionForTest(false)
	cSess.DtlsConnected.Store(true)

	cSess.DPDTimer()
	t.Cleanup(func() { cSess.Close() })

	select {
	case <-cSess.PayloadOutTLS:
	case <-time.After(12 * time.Second):
		t.Fatal("expected TLS DPD probe")
	}

	select {
	case <-cSess.PayloadOutDTLS:
	case <-time.After(2 * time.Second):
		t.Fatal("expected DTLS DPD probe")
	}
}

func TestReadDeadTimerSetsResetFlags(t *testing.T) {
	_, cSess := newConnSessionForTest(false)
	cSess.ResetTLSReadDead.Store(false)
	cSess.ResetDTLSReadDead.Store(false)

	cSess.ReadDeadTimer()
	t.Cleanup(func() { cSess.Close() })

	deadline := time.After(5 * time.Second)
	for {
		if cSess.ResetTLSReadDead.Load() && cSess.ResetDTLSReadDead.Load() {
			return
		}
		select {
		case <-deadline:
			t.Fatal("read dead timer did not set reset flags")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func TestStatMarshalJSONUsesAtomicValues(t *testing.T) {
	s := &stat{}
	s.BytesSent.Add(123)
	s.BytesReceived.Add(456)

	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}

	var got struct {
		BytesSent     uint64 `json:"bytesSent"`
		BytesReceived uint64 `json:"bytesReceived"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}
	if got.BytesSent != 123 || got.BytesReceived != 456 {
		t.Fatalf("unexpected marshaled values: %+v", got)
	}
}
