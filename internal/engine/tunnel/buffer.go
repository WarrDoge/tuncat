package tunnel

import (
	"sync"

	"github.com/WarrDoge/tuncat/internal/engine/protocol"
)

const BufferSize = 2048

var pool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, BufferSize)
		pl := protocol.Payload{
			Type: 0x00,
			Data: b,
		}
		return &pl
	},
}

func getPayloadBuffer() *protocol.Payload {
	pl := pool.Get().(*protocol.Payload)
	return pl
}

func putPayloadBuffer(pl *protocol.Payload) {
	if cap(pl.Data) != BufferSize {
		return
	}

	pl.Type = protocol.PayloadData
	pl.Data = pl.Data[:BufferSize]
	pool.Put(pl)
}
