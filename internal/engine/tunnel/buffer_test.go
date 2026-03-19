package tunnel

import (
	"testing"

	"tuncat/internal/engine/protocol"
)

func TestPayloadBufferGetPutResetsPayload(t *testing.T) {
	pl := getPayloadBuffer()
	pl.Type = protocol.PayloadDPDReq
	pl.Data = pl.Data[:64]

	putPayloadBuffer(pl)

	got := getPayloadBuffer()
	if got.Type != protocol.PayloadData {
		t.Fatalf("payload type = %#x, want %#x", got.Type, protocol.PayloadData)
	}
	if len(got.Data) != BufferSize {
		t.Fatalf("payload len = %d, want %d", len(got.Data), BufferSize)
	}
	if cap(got.Data) != BufferSize {
		t.Fatalf("payload cap = %d, want %d", cap(got.Data), BufferSize)
	}
}

func TestPayloadBufferRejectsOversizedBuffer(t *testing.T) {
	over := &protocol.Payload{Type: protocol.PayloadDPDReq, Data: make([]byte, BufferSize+1)}
	putPayloadBuffer(over)

	got := getPayloadBuffer()
	if got == over {
		t.Fatal("oversized payload was returned to pool")
	}
	if cap(got.Data) != BufferSize {
		t.Fatalf("pooled payload cap = %d, want %d", cap(got.Data), BufferSize)
	}
}
