package tunnel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/WarrDoge/tuncat/internal/engine/protocol"
)

// makeCSTPFrame builds a valid CSTP frame header + [size] bytes of payload data.
func makeCSTPFrame(payloadType byte, dataLen int) []byte {
	buf := make([]byte, 8+dataLen)
	copy(buf[:4], protocol.Header[:4])
	binary.BigEndian.PutUint16(buf[4:6], uint16(dataLen))
	buf[6] = payloadType
	buf[7] = 0x00
	return buf
}

func TestReadCSTPFrame_NormalFrame(t *testing.T) {
	frame := makeCSTPFrame(protocol.PayloadData, 100)
	rd := bufio.NewReader(bytes.NewReader(frame))

	pl := getPayloadBuffer()
	n, err := readCSTPFrame(rd, pl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(frame) {
		t.Fatalf("bytes read = %d, want %d", n, len(frame))
	}
}

func TestReadCSTPFrame_OversizedDataLen(t *testing.T) {
	// dataLen = 3000, which exceeds BufferSize - minHeaderLen = 2048 - 8 = 2040
	frame := makeCSTPFrame(protocol.PayloadData, 3000)
	rd := bufio.NewReader(bytes.NewReader(frame))

	pl := getPayloadBuffer()
	_, err := readCSTPFrame(rd, pl)
	if err == nil {
		t.Fatal("expected error for oversized data length, got nil")
	}
}

func TestReadCSTPFrame_ShortHeader(t *testing.T) {
	// Only 4 bytes — not even a full CSTP header (need 8)
	frame := []byte{0x53, 0x54, 0x46, 0x01}
	rd := bufio.NewReader(bytes.NewReader(frame))

	pl := getPayloadBuffer()
	_, err := readCSTPFrame(rd, pl)
	if err == nil {
		t.Fatal("expected error for short header, got nil")
	}
}

func TestReadCSTPFrame_ShortPayload(t *testing.T) {
	// Header says 100 bytes of data, but only 8+50 bytes are available
	frame := makeCSTPFrame(protocol.PayloadData, 100)
	frame = frame[:8+50] // truncate
	rd := bufio.NewReader(bytes.NewReader(frame))

	pl := getPayloadBuffer()
	_, err := readCSTPFrame(rd, pl)
	if err == nil {
		t.Fatal("expected error for partial frame, got nil")
	}
}

func TestReadCSTPFrame_ExactBufferCapacity(t *testing.T) {
	// dataLen = BufferSize - minHeaderLen = 2040 — exact fit
	dataLen := BufferSize - minHeaderLen
	frame := makeCSTPFrame(protocol.PayloadData, dataLen)
	rd := bufio.NewReader(bytes.NewReader(frame))

	pl := getPayloadBuffer()
	_, err := readCSTPFrame(rd, pl)
	if err != nil {
		t.Fatalf("unexpected error for exact capacity frame: %v", err)
	}
}

func TestReadCSTPFrame_NonDataPayload(t *testing.T) {
	// DPD-REQ frame is header-only (type byte 6 = 0x03)
	frame := makeCSTPFrame(protocol.PayloadDPDReq, 0)
	rd := bufio.NewReader(bytes.NewReader(frame))

	pl := getPayloadBuffer()
	n, err := readCSTPFrame(rd, pl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(frame) {
		t.Fatalf("bytes read = %d, want %d", n, len(frame))
	}
	if pl.Data[6] != protocol.PayloadDPDReq {
		t.Fatalf("payload type = %#x, want %#x", pl.Data[6], protocol.PayloadDPDReq)
	}
}

func TestReadCSTPFrame_EOF(t *testing.T) {
	rd := bufio.NewReader(bytes.NewReader(nil))

	pl := getPayloadBuffer()
	_, err := readCSTPFrame(rd, pl)
	if err == nil {
		t.Fatal("expected EOF error, got nil")
	}
}
