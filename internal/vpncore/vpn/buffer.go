package vpn

import (
	"sync"

	"tuncat/internal/vpncore/proto"
)

const BufferSize = 2048

var pool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, BufferSize)
		pl := proto.Payload{
			Type: 0x00,
			Data: b,
		}
		return &pl
	},
}

func getPayloadBuffer() *proto.Payload {
	pl := pool.Get().(*proto.Payload)
	return pl
}

func putPayloadBuffer(pl *proto.Payload) {
	if cap(pl.Data) != BufferSize {
		return
	}

	pl.Type = proto.PayloadData
	pl.Data = pl.Data[:BufferSize]
	pool.Put(pl)
}
