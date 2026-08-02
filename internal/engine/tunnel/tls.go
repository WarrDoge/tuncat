package tunnel

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net/http"
	"time"

	engineconfig "github.com/WarrDoge/tuncat/internal/engine/config"
	"github.com/WarrDoge/tuncat/internal/engine/protocol"
	enginesession "github.com/WarrDoge/tuncat/internal/engine/session"
)

// minHeaderLen is the CSTP header size: 4 magic bytes + 2 length + 1 type + 1 reserved.
const minHeaderLen = 8

// readCSTPFrame reads one CSTP frame from bufR into pl and validates its integrity.
// It reports three kinds of read errors:
//   - io.EOF / any io error from bufR.Read
//   - errShortHeader when fewer than minHeaderLen bytes were read
//   - errOversizedFrame when the declared data length exceeds buffer capacity
//   - errPartialFrame when fewer bytes were read than the header+body require
//
// readCSTPFrame returns the number of raw bytes consumed from the wire (for
// statistics) on success.
func readCSTPFrame(bufR *bufio.Reader, pl *protocol.Payload) (int, error) {
	bytesReceived, err := bufR.Read(pl.Data)
	if err != nil {
		return 0, err
	}

	// Guard against partial TLS records that don't contain a full CSTP header.
	if bytesReceived < minHeaderLen {
		return 0, fmt.Errorf("tls short read: got %d bytes, need at least %d for CSTP header", bytesReceived, minHeaderLen)
	}

	// Validate declared payload length against buffer capacity.
	dataLen := binary.BigEndian.Uint16(pl.Data[4:6])
	maxDataLen := BufferSize - minHeaderLen
	if dataLen > uint16(maxDataLen) {
		return 0, fmt.Errorf("tls oversized frame: declared data length %d exceeds max %d", dataLen, maxDataLen)
	}
	// Guard against partial reads where the frame body was split across TLS records.
	if bytesReceived < minHeaderLen+int(dataLen) {
		return 0, fmt.Errorf("tls partial frame: got %d bytes, need %d for frame body", bytesReceived, minHeaderLen+int(dataLen))
	}

	return bytesReceived, nil
}

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
		bytesReceived, err = readCSTPFrame(bufR, pl)
		if err != nil {
			engineconfig.Error("tls server to payloadIn error:", err)
			return
		}

		// CSTP framing puts packet type at byte 6.
		switch pl.Data[6] {
		case protocol.PayloadData:
			dataLen := binary.BigEndian.Uint16(pl.Data[4:6])
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
