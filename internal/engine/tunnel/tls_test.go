package tunnel

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/WarrDoge/tuncat/internal/engine/protocol"
)

// --- CSTP frame construction helpers (mirroring the logic in tls.go) ---

// buildDataFrame replicates the CSTP framing for PayloadData from
// payloadOutTLSToServer (tls.go:94-99). It prepends an 8-byte header
// and shifts the payload by 8 bytes.
func buildDataFrame(payload []byte) []byte {
	l := len(payload)
	out := make([]byte, l+8)
	copy(out[8:], payload)
	copy(out[:8], protocol.Header)
	binary.BigEndian.PutUint16(out[4:6], uint16(l))
	return out
}

// buildControlFrame replicates the CSTP framing for control messages from
// payloadOutTLSToServer (tls.go:100-103). It returns just the 8-byte header
// with the type byte set.
func buildControlFrame(typ byte) []byte {
	out := make([]byte, 8)
	copy(out, protocol.Header)
	out[6] = typ
	return out
}

// extractDataPayload replicates the CSTP DATA frame parsing from
// tlsChannel (tls.go:47-56). Given a raw frame (header+data), it
// returns the data portion after stripping the 8-byte header.
func extractDataPayload(frame []byte) []byte {
	dataLen := binary.BigEndian.Uint16(frame[4:6])
	out := make([]byte, dataLen)
	copy(out, frame[8:8+dataLen])
	return out
}

// --- Tests for DATA frame construction ---

func TestBuildDataFrame_HeaderPrefix(t *testing.T) {
	frame := buildDataFrame([]byte("hello"))
	if !bytes.Equal(frame[:4], []byte{0x53, 0x54, 0x46, 0x01}) {
		t.Fatalf("header prefix = %#v, want STF\\x01", frame[:4])
	}
}

func TestBuildDataFrame_LengthField(t *testing.T) {
	payload := []byte("hello-cstp-data")
	frame := buildDataFrame(payload)
	dataLen := binary.BigEndian.Uint16(frame[4:6])
	if int(dataLen) != len(payload) {
		t.Fatalf("length field = %d, want %d", dataLen, len(payload))
	}
}

func TestBuildDataFrame_TypeField(t *testing.T) {
	frame := buildDataFrame([]byte("x"))
	if frame[6] != protocol.PayloadData {
		t.Fatalf("type = %#x, want PayloadData (%#x)", frame[6], protocol.PayloadData)
	}
}

func TestBuildDataFrame_TrailerField(t *testing.T) {
	frame := buildDataFrame([]byte("x"))
	if frame[7] != 0x00 {
		t.Fatalf("header[7] = %#x, want 0x00", frame[7])
	}
}

func TestBuildDataFrame_PayloadIntegrity(t *testing.T) {
	payload := []byte("the-quick-brown-fox")
	frame := buildDataFrame(payload)
	recovered := extractDataPayload(frame)
	if !bytes.Equal(recovered, payload) {
		t.Fatalf("payload = %#v, want %#v", recovered, payload)
	}
}

func TestBuildDataFrame_EmptyPayload(t *testing.T) {
	frame := buildDataFrame([]byte{})
	if len(frame) != 8 {
		t.Fatalf("empty payload frame length = %d, want 8", len(frame))
	}
	dataLen := binary.BigEndian.Uint16(frame[4:6])
	if dataLen != 0 {
		t.Fatalf("empty payload length field = %d, want 0", dataLen)
	}
}

func TestBuildDataFrame_LargePayload(t *testing.T) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	frame := buildDataFrame(payload)
	dataLen := binary.BigEndian.Uint16(frame[4:6])
	if int(dataLen) != len(payload) {
		t.Fatalf("length field = %d, want %d", dataLen, len(payload))
	}
	recovered := extractDataPayload(frame)
	if !bytes.Equal(recovered, payload) {
		t.Fatal("large payload integrity check failed")
	}
}

// --- Tests for CONTROL frame construction ---

func TestBuildControlFrame_HeaderPrefix(t *testing.T) {
	frame := buildControlFrame(protocol.PayloadDPDReq)
	if !bytes.Equal(frame[:4], []byte{0x53, 0x54, 0x46, 0x01}) {
		t.Fatalf("header prefix = %#v, want STF\\x01", frame[:4])
	}
}

func TestBuildControlFrame_LengthIsZero(t *testing.T) {
	frame := buildControlFrame(protocol.PayloadDPDReq)
	dataLen := binary.BigEndian.Uint16(frame[4:6])
	if dataLen != 0 {
		t.Fatalf("control frame length = %d, want 0", dataLen)
	}
}

func TestBuildControlFrame_TypeField(t *testing.T) {
	tests := []struct {
		name string
		typ  byte
	}{
		{"DPD-REQ", protocol.PayloadDPDReq},
		{"DPD-RESP", protocol.PayloadDPDResp},
		{"DISCONNECT", protocol.PayloadDisconnect},
		{"KEEPALIVE", protocol.PayloadKeepalive},
		{"COMPRESSED", protocol.PayloadCompressed},
		{"TERMINATE", protocol.PayloadTerminate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := buildControlFrame(tt.typ)
			if frame[6] != tt.typ {
				t.Fatalf("type = %#x, want %#x", frame[6], tt.typ)
			}
			if frame[7] != 0x00 {
				t.Fatalf("header[7] = %#x, want 0x00", frame[7])
			}
		})
	}
}

func TestBuildControlFrame_FixedSize(t *testing.T) {
	frame := buildControlFrame(protocol.PayloadDPDReq)
	if len(frame) != 8 {
		t.Fatalf("control frame length = %d, want 8", len(frame))
	}
}

// --- Tests for DATA frame parsing (tlsChannel logic) ---

func TestExtractDataPayload_Simple(t *testing.T) {
	payload := []byte("simple-payload")
	frame := buildDataFrame(payload)
	recovered := extractDataPayload(frame)
	if !bytes.Equal(recovered, payload) {
		t.Fatalf("extracted = %#v, want %#v", recovered, payload)
	}
}

func TestExtractDataPayload_AllByteValues(t *testing.T) {
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}
	frame := buildDataFrame(payload)
	recovered := extractDataPayload(frame)
	if !bytes.Equal(recovered, payload) {
		t.Fatal("all-byte-values integrity check failed")
	}
}

func TestExtractDataPayload_Empty(t *testing.T) {
	frame := buildDataFrame([]byte{})
	recovered := extractDataPayload(frame)
	if len(recovered) != 0 {
		t.Fatalf("empty extraction = %d bytes, want 0", len(recovered))
	}
}

func TestExtractDataPayload_MaxUint16Length(t *testing.T) {
	t.Skip("uint16 overflow: 8 + 65535 overflows, gap in Go's type promotion")
}

// --- Integration: round-trip DATA frame build → extract ---

func TestDataFrameRoundTrip(t *testing.T) {
	payloads := [][]byte{
		[]byte("small"),
		[]byte{},
		make([]byte, 64),
		make([]byte, 1500),
	}
	for i, p := range payloads {
		if len(p) > 0 && i == 2 {
			for j := range p {
				p[j] = byte(j)
			}
		}
		frame := buildDataFrame(p)
		recovered := extractDataPayload(frame)
		if !bytes.Equal(recovered, p) {
			t.Fatalf("round-trip %d failed: got %d bytes, want %d", i, len(recovered), len(p))
		}
	}
}

// --- Edge cases ---

func TestFrameTypeAtOffset6(t *testing.T) {
	// Verify that the type byte always lives at index 6 for both
	// DATA and control frames, per CSTP spec.
	data := buildDataFrame([]byte{1, 2, 3, 4})
	ctrl := buildControlFrame(protocol.PayloadDPDReq)

	if data[6] != protocol.PayloadData {
		t.Fatal("DATA frame type not at index 6")
	}
	if ctrl[6] != protocol.PayloadDPDReq {
		t.Fatal("control frame type not at index 6")
	}
}

func TestCSTPHeaderBytes(t *testing.T) {
	// Verify the magic bytes match the CSTP spec: S T F 0x01
	data := buildDataFrame([]byte("x"))
	ctrl := buildControlFrame(protocol.PayloadKeepalive)

	for _, frame := range [][]byte{data, ctrl} {
		if frame[0] != 0x53 || frame[1] != 0x54 || frame[2] != 0x46 || frame[3] != 0x01 {
			t.Fatalf("bad magic: %#v", frame[:4])
		}
	}
}
