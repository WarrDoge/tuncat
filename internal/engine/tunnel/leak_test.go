package tunnel

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/WarrDoge/tuncat/internal/engine/device"
	"github.com/WarrDoge/tuncat/internal/engine/protocol"
	enginesession "github.com/WarrDoge/tuncat/internal/engine/session"
)

// assertNoBufferLeak checks a code path hands its pooled buffer back, by
// pointer identity rather than by counting.
//
// A put immediately followed by a get on the same goroutine returns the very
// same object, because sync.Pool parks it in the per-P private slot. So: park a
// marker, run the path, then get again. If the path returned every buffer it
// took, the marker comes back. If it stranded one, the pool had to allocate and
// the pointer differs.
func assertNoBufferLeak(t *testing.T, drive func()) {
	t.Helper()

	marker := getPayloadBuffer()
	putPayloadBuffer(marker)

	drive()

	if got := getPayloadBuffer(); got != marker {
		t.Fatal("pooled buffer was not returned: the exercised path leaked it")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("synthetic read error") }

type fakeDevice struct{ readErr error }

func (d *fakeDevice) File() *os.File { return nil }
func (d *fakeDevice) Read(b []byte, _ int) (int, error) {
	if d.readErr != nil {
		return 0, d.readErr
	}
	copy(b, []byte("AAAA"))
	return 4, nil
}
func (d *fakeDevice) Write(b []byte, _ int) (int, error) { return len(b), nil }
func (d *fakeDevice) Flush() error                       { return nil }
func (d *fakeDevice) MTU() (int, error)                  { return 1500, nil }
func (d *fakeDevice) Name() (string, error)              { return "tuncat", nil }
func (d *fakeDevice) Events() <-chan device.Event        { return nil }
func (d *fakeDevice) Close() error                       { return nil }

func testConnSession(t *testing.T) *enginesession.ConnSession {
	t.Helper()
	cSess := (&enginesession.Session{}).NewConnSession(&http.Header{}, "127.0.0.1", true)
	cSess.ServerAddress = "127.0.0.1"
	cSess.ResetTLSReadDead.Store(false)
	return cSess
}

// cstpFrame builds a well-formed CSTP frame.
func cstpFrame(ptype byte, data []byte) []byte {
	buf := make([]byte, len(protocol.Header)+len(data))
	copy(buf, protocol.Header)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(data)))
	buf[6] = ptype
	copy(buf[len(protocol.Header):], data)
	return buf
}

// driveTLS runs tlsChannel over a canned server-side byte stream. tlsChannel
// only uses the *tls.Conn for deadlines and teardown, so an unhandshaken pipe
// is enough; the frames come from bufR.
func driveTLS(t *testing.T, cSess *enginesession.ConnSession, stream []byte) {
	t.Helper()
	c, srv := net.Pipe()
	defer func() { _ = srv.Close() }()
	defer func() { _ = c.Close() }()
	resp := &http.Response{Body: io.NopCloser(bytes.NewReader(nil))}

	var r io.Reader
	if stream == nil {
		r = errReader{}
	} else {
		r = bytes.NewReader(stream)
	}
	tlsChannel(tls.Client(c, &tls.Config{}), bufio.NewReader(r), cSess, resp)
}

func TestTLSReadErrorReturnsBuffer(t *testing.T) {
	assertNoBufferLeak(t, func() { driveTLS(t, testConnSession(t), nil) })
}

// A DPD-RESP is logged and dropped: the loop keeps going, so the buffer has to
// come back before the next iteration acquires another one.
func TestTLSDPDRespReturnsBuffer(t *testing.T) {
	assertNoBufferLeak(t, func() {
		driveTLS(t, testConnSession(t), cstpFrame(protocol.PayloadDPDResp, nil))
	})
}

// An unrecognised payload type falls to default and must not strand the buffer.
func TestTLSUnknownTypeReturnsBuffer(t *testing.T) {
	assertNoBufferLeak(t, func() {
		driveTLS(t, testConnSession(t), cstpFrame(0x7f, []byte("junk")))
	})
}

// A frame whose declared length runs past the bytes received is refused; the
// buffer must be released on that path too.
func TestTLSMalformedFrameReturnsBuffer(t *testing.T) {
	assertNoBufferLeak(t, func() {
		bad := cstpFrame(protocol.PayloadData, []byte("ab"))
		binary.BigEndian.PutUint16(bad[4:6], 0xFFFF) // lie about the length
		driveTLS(t, testConnSession(t), bad)
	})
}

func TestTLSCloseChanOnDataReturnsBuffer(t *testing.T) {
	assertNoBufferLeak(t, func() {
		cSess := testConnSession(t)
		for len(cSess.PayloadIn) < cap(cSess.PayloadIn) {
			cSess.PayloadIn <- &protocol.Payload{Data: make([]byte, BufferSize)}
		}
		cSess.Close()
		driveTLS(t, cSess, cstpFrame(protocol.PayloadData, []byte("hello")))
	})
}

func TestTLSCloseChanOnDPDReqReturnsBuffer(t *testing.T) {
	assertNoBufferLeak(t, func() {
		cSess := testConnSession(t)
		cSess.PayloadOutTLS = nil // a send blocks forever, so CloseChan wins
		cSess.Close()
		driveTLS(t, cSess, cstpFrame(protocol.PayloadDPDReq, nil))
	})
}

func TestTUNReadErrorReturnsBuffer(t *testing.T) {
	assertNoBufferLeak(t, func() {
		tunToPayloadOut(&fakeDevice{readErr: errors.New("synthetic tun read error")}, testConnSession(t), 0)
	})
}

func TestTUNCloseChanReturnsBuffer(t *testing.T) {
	assertNoBufferLeak(t, func() {
		cSess := testConnSession(t)
		for len(cSess.PayloadOutTLS) < cap(cSess.PayloadOutTLS) {
			cSess.PayloadOutTLS <- &protocol.Payload{Data: make([]byte, BufferSize)}
		}
		cSess.Close()
		tunToPayloadOut(&fakeDevice{}, cSess, 0)
	})
}
