package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// frame builds a CSTP frame with a declared length that need not match the
// bytes actually appended, so tests can express a lying length field.
func frame(ptype byte, declaredLen int, data []byte) []byte {
	buf := make([]byte, len(Header)+len(data))
	copy(buf, Header)
	binary.BigEndian.PutUint16(buf[4:6], uint16(declaredLen))
	buf[6] = ptype
	copy(buf[len(Header):], data)
	return buf
}

func TestParseFrame(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		wantErr error
		wantLen int
	}{
		{"data frame", frame(PayloadData, 4, []byte("abcd")), nil, 4},
		{"header only", frame(PayloadKeepalive, 0, nil), nil, 0},
		{"short of header", []byte{0x53, 0x54, 0x46}, ErrShortFrame, 0},
		{"empty", nil, ErrShortFrame, 0},
		{"bad magic", frame(PayloadData, 0, nil)[:8:8], nil, 0},
		// The crash: a length field far larger than the bytes received.
		{"length past end", frame(PayloadData, 0xFFFF, []byte("ab")), ErrPayloadLength, 0},
		{"length one past end", frame(PayloadData, 3, []byte("ab")), ErrPayloadLength, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "bad magic" {
				tc.buf = append([]byte(nil), tc.buf...)
				tc.buf[0] = 0x00
				tc.wantErr = ErrBadMagic
			}
			_, payload, err := ParseFrame(tc.buf)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if err == nil && len(payload) != tc.wantLen {
				t.Fatalf("payload len = %d, want %d", len(payload), tc.wantLen)
			}
		})
	}
}

// TestParseFrameRejectsLengthBeyondBytesRead is the pooled-buffer case: the
// caller must pass only the bytes it received. A frame declaring more than it
// delivered must be refused rather than exposing whatever the pool left behind.
func TestParseFrameRejectsLengthBeyondBytesRead(t *testing.T) {
	pooled := bytes.Repeat([]byte("S"), 2048) // stale bytes from an earlier frame
	received := frame(PayloadData, 1024, []byte("hi"))
	copy(pooled, received)

	if _, _, err := ParseFrame(pooled[:len(received)]); !errors.Is(err, ErrPayloadLength) {
		t.Fatalf("err = %v, want ErrPayloadLength", err)
	}

	// Passing the whole pooled buffer is exactly the mistake the doc comment
	// warns about: it "succeeds" and hands back stale bytes.
	_, payload, err := ParseFrame(pooled)
	if err != nil {
		t.Fatalf("unexpected err on full buffer: %v", err)
	}
	if !bytes.Contains(payload, []byte("SSSS")) {
		t.Fatal("expected the full-buffer parse to expose stale bytes; " +
			"if this no longer holds, ParseFrame's contract changed")
	}
}

// slowReader hands out at most n bytes per Read, the way a TCP stream can
// deliver a frame in pieces.
type slowReader struct {
	data []byte
	n    int
}

func (r *slowReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(min(r.n, len(p)), len(r.data))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

// TestReadFrameReassemblesSplitFrame is why ReadFrame exists: a single Read on
// a stream is not frame-aligned, so parsing one read's worth would reject a
// frame that merely arrived in two segments.
func TestReadFrameReassemblesSplitFrame(t *testing.T) {
	buf := make([]byte, 2048)
	want := []byte("hello world")

	for _, chunk := range []int{1, 3, 7, 8, 13} {
		r := &slowReader{data: frame(PayloadData, len(want), want), n: chunk}
		ptype, payload, err := ReadFrame(r, buf)
		if err != nil {
			t.Fatalf("chunk %d: %v", chunk, err)
		}
		if ptype != PayloadData || !bytes.Equal(payload, want) {
			t.Fatalf("chunk %d: got type %#x payload %q", chunk, ptype, payload)
		}
	}
}

// Two frames in one delivery: the second must survive for the next call.
func TestReadFrameLeavesTrailingFrameBuffered(t *testing.T) {
	stream := append(frame(PayloadData, 2, []byte("ab")), frame(PayloadDPDReq, 0, nil)...)
	r := bytes.NewReader(stream)
	buf := make([]byte, 2048)

	if _, payload, err := ReadFrame(r, buf); err != nil || !bytes.Equal(payload, []byte("ab")) {
		t.Fatalf("first frame: payload %q err %v", payload, err)
	}
	ptype, _, err := ReadFrame(r, buf)
	if err != nil || ptype != PayloadDPDReq {
		t.Fatalf("second frame: type %#x err %v", ptype, err)
	}
}

// A declared length larger than the caller's buffer is unrecoverable and must
// be reported rather than used to slice.
func TestReadFrameRejectsOversizedLength(t *testing.T) {
	buf := make([]byte, 64)
	r := bytes.NewReader(frame(PayloadData, 0xFFFF, []byte("ab")))
	if _, _, err := ReadFrame(r, buf); !errors.Is(err, ErrPayloadLength) {
		t.Fatalf("err = %v, want ErrPayloadLength", err)
	}
}

// FuzzParseFrame drives the parser with arbitrary bytes. Before the length
// check existed the equivalent slice panicked; see the seed below.
func FuzzParseFrame(f *testing.F) {
	f.Add(frame(PayloadData, 4, []byte("abcd")))
	f.Add(frame(PayloadData, 0xFFFF, []byte("ab"))) // the crasher
	f.Add(frame(PayloadDPDReq, 0, nil))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, buf []byte) {
		ptype, payload, err := ParseFrame(buf)
		if err != nil {
			return
		}
		if len(payload) > len(buf)-len(Header) {
			t.Fatalf("payload %d exceeds buffer %d", len(payload), len(buf))
		}
		_ = ptype
	})
}
