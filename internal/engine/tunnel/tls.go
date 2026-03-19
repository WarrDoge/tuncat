package tunnel

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"net/http"
	"time"

	engineconfig "github.com/WarrDoge/tuncat/internal/engine/config"
	"github.com/WarrDoge/tuncat/internal/engine/protocol"
	enginesession "github.com/WarrDoge/tuncat/internal/engine/session"
)

func tlsChannel(conn *tls.Conn, bufR *bufio.Reader, cSess *enginesession.ConnSession, resp *http.Response) {
	defer func() {
		engineconfig.Info("tls channel exit")
		resp.Body.Close()
		_ = conn.Close()
		cSess.Close()
	}()
	var (
		err           error
		bytesReceived int
		dataLen       uint16
		dead          = time.Duration(cSess.TLSDpdTime+5) * time.Second
	)

	go payloadOutTLSToServer(conn, cSess)

	// Read CSTP frames from server and forward DATA frames to PayloadIn.
	for {
		if cSess.ResetTLSReadDead.Load() {
			_ = conn.SetReadDeadline(time.Now().Add(dead))
			cSess.ResetTLSReadDead.Store(false)
		}

		pl := getPayloadBuffer()
		bytesReceived, err = bufR.Read(pl.Data)
		if err != nil {
			engineconfig.Error("tls server to payloadIn error:", err)
			return
		}

		// CSTP framing puts packet type at byte 6.
		switch pl.Data[6] {
		case protocol.PayloadData:
			dataLen = binary.BigEndian.Uint16(pl.Data[4:6])
			copy(pl.Data, pl.Data[8:8+dataLen])
			pl.Data = pl.Data[:dataLen]

			select {
			case cSess.PayloadIn <- pl:
			case <-cSess.CloseChan:
				return
			}
		case protocol.PayloadDPDResp:
			engineconfig.Debug("tls receive DPD-RESP")
		case protocol.PayloadDPDReq:
			// Reply via the same outbound path so keepalive timing stays consistent.
			pl.Type = protocol.PayloadDPDResp
			select {
			case cSess.PayloadOutTLS <- pl:
			case <-cSess.CloseChan:
				return
			}
		}
		cSess.Stat.BytesReceived.Add(uint64(bytesReceived))
	}
}

// payloadOutTLSToServer wraps payloads with CSTP framing and sends them over TLS.
func payloadOutTLSToServer(conn *tls.Conn, cSess *enginesession.ConnSession) {
	defer func() {
		engineconfig.Info("tls payloadOut to server exit")
		_ = conn.Close()
		cSess.Close()
	}()

	var (
		err       error
		bytesSent int
		pl        *protocol.Payload
	)

	for {
		select {
		case pl = <-cSess.PayloadOutTLS:
		case <-cSess.CloseChan:
			return
		}

		// PayloadData is raw IP data; all control messages use header-only frames.
		if pl.Type == protocol.PayloadData {
			l := len(pl.Data)
			pl.Data = pl.Data[:l+8]
			copy(pl.Data[8:], pl.Data)
			copy(pl.Data[:8], protocol.Header)
			binary.BigEndian.PutUint16(pl.Data[4:6], uint16(l))
		} else {
			pl.Data = append(pl.Data[:0], protocol.Header...)
			pl.Data[6] = pl.Type
		}
		bytesSent, err = conn.Write(pl.Data)
		if err != nil {
			engineconfig.Error("tls payloadOut to server error:", err)
			return
		}
		cSess.Stat.BytesSent.Add(uint64(bytesSent))

		putPayloadBuffer(pl)
	}
}
