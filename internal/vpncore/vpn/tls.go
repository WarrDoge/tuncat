package vpn

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"net/http"
	"time"

	"tuncat/internal/vpncore/base"
	"tuncat/internal/vpncore/proto"
	"tuncat/internal/vpncore/session"
)

func tlsChannel(conn *tls.Conn, bufR *bufio.Reader, cSess *session.ConnSession, resp *http.Response) {
	defer func() {
		base.Info("tls channel exit")
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
			base.Error("tls server to payloadIn error:", err)
			return
		}

		// CSTP framing puts packet type at byte 6.
		switch pl.Data[6] {
		case proto.PayloadData:
			dataLen = binary.BigEndian.Uint16(pl.Data[4:6])
			copy(pl.Data, pl.Data[8:8+dataLen])
			pl.Data = pl.Data[:dataLen]

			select {
			case cSess.PayloadIn <- pl:
			case <-cSess.CloseChan:
				return
			}
		case proto.PayloadDPDResp:
			base.Debug("tls receive DPD-RESP")
		case proto.PayloadDPDReq:
			// Reply via the same outbound path so keepalive timing stays consistent.
			pl.Type = proto.PayloadDPDResp
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
func payloadOutTLSToServer(conn *tls.Conn, cSess *session.ConnSession) {
	defer func() {
		base.Info("tls payloadOut to server exit")
		_ = conn.Close()
		cSess.Close()
	}()

	var (
		err       error
		bytesSent int
		pl        *proto.Payload
	)

	for {
		select {
		case pl = <-cSess.PayloadOutTLS:
		case <-cSess.CloseChan:
			return
		}

		// PayloadData is raw IP data; all control messages use header-only frames.
		if pl.Type == proto.PayloadData {
			l := len(pl.Data)
			pl.Data = pl.Data[:l+8]
			copy(pl.Data[8:], pl.Data)
			copy(pl.Data[:8], proto.Header)
			binary.BigEndian.PutUint16(pl.Data[4:6], uint16(l))
		} else {
			pl.Data = append(pl.Data[:0], proto.Header...)
			pl.Data[6] = pl.Type
		}
		bytesSent, err = conn.Write(pl.Data)
		if err != nil {
			base.Error("tls payloadOut to server error:", err)
			return
		}
		cSess.Stat.BytesSent.Add(uint64(bytesSent))

		putPayloadBuffer(pl)
	}
}
