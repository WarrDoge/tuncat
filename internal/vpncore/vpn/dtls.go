package vpn

import (
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"time"

	"github.com/pion/dtls/v3"
	"tuncat/internal/vpncore/base"
	"tuncat/internal/vpncore/proto"
	"tuncat/internal/vpncore/session"
)

func dtlsChannel(cSess *session.ConnSession, preMasterSecret []byte) {
	var (
		conn          *dtls.Conn
		dSess         *session.DtlsSession
		err           error
		bytesReceived int
		dead          = time.Duration(cSess.DTLSDpdTime+5) * time.Second
	)
	defer func() {
		base.Info("dtls channel exit")
		if conn != nil {
			_ = conn.Close()
		}
		if dSess != nil {
			dSess.Close()
		}
	}()

	port, _ := strconv.Atoi(cSess.DTLSPort)
	addr := &net.UDPAddr{IP: net.ParseIP(cSess.ServerAddress), Port: port}

	id, _ := hex.DecodeString(cSess.DTLSId)

	config := &dtls.Config{
		// InsecureSkipVerify is intentional: DTLS is authenticated via
		// a pre-master secret exchanged over the already-verified TLS CSTP
		// channel, bound to the session by X-DTLS-Session-ID.
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.DisableExtendedMasterSecret,
		CipherSuites: func() []dtls.CipherSuiteID {
			switch cSess.DTLSCipherSuite {
			case "ECDHE-ECDSA-AES128-GCM-SHA256":
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
			case "ECDHE-RSA-AES128-GCM-SHA256":
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
			case "ECDHE-ECDSA-AES256-GCM-SHA384":
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
			case "ECDHE-RSA-AES256-GCM-SHA384":
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
			default:
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
			}
		}(),
		SessionStore: &SessionStore{dtls.Session{ID: id, Secret: preMasterSecret}},
	}

	conn, err = dtls.Dial("udp4", addr, config)
	// Always close DtlsSetupChan so status/readiness waiters are unblocked.
	if err != nil {
		base.Error(err)
		close(cSess.DtlsSetupChan)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = conn.HandshakeContext(ctx); err != nil {
		base.Error(err)
		close(cSess.DtlsSetupChan)
		return
	}

	cSess.DtlsConnected.Store(true)
	dSess = cSess.DSess
	close(cSess.DtlsSetupChan)

	// Record negotiated suite for diagnostics and status output.
	state, success := conn.ConnectionState()
	if success {
		cSess.DTLSCipherSuite = dtls.CipherSuiteName(state.CipherSuiteID)
	} else {
		cSess.DTLSCipherSuite = ""
	}

	base.Info("dtls channel negotiation succeeded")

	go payloadOutDTLSToServer(conn, dSess, cSess)

	// Read DTLS records and forward payload DATA frames to PayloadIn.
	for {
		if cSess.ResetDTLSReadDead.Load() {
			_ = conn.SetReadDeadline(time.Now().Add(dead))
			cSess.ResetDTLSReadDead.Store(false)
		}

		pl := getPayloadBuffer()
		bytesReceived, err = conn.Read(pl.Data)
		if err != nil {
			base.Error("dtls server to payloadIn error:", err)
			return
		}

		// Legacy DTLS packet type is encoded in the first byte.
		switch pl.Data[0] {
		case proto.PayloadKeepalive:
		case proto.PayloadDisconnect:
			return
		case proto.PayloadDPDReq:
			pl.Type = proto.PayloadDPDResp
			select {
			case cSess.PayloadOutDTLS <- pl:
			case <-dSess.CloseChan:
			}
		case proto.PayloadDPDResp:
			base.Debug("dtls receive DPD-RESP")
		case proto.PayloadData:
			pl.Data = append(pl.Data[:0], pl.Data[1:bytesReceived]...)
			select {
			case cSess.PayloadIn <- pl:
			case <-dSess.CloseChan:
				return
			}
		}
		cSess.Stat.BytesReceived.Add(uint64(bytesReceived))
	}
}

// payloadOutDTLSToServer serializes DATA/control payloads for DTLS transport.
func payloadOutDTLSToServer(conn *dtls.Conn, dSess *session.DtlsSession, cSess *session.ConnSession) {
	defer func() {
		base.Info("dtls payloadOut to server exit")
		_ = conn.Close()
		dSess.Close()
	}()

	var (
		err       error
		bytesSent int
		pl        *proto.Payload
	)

	for {
		select {
		case pl = <-cSess.PayloadOutDTLS:
		case <-dSess.CloseChan:
			return
		}

		if pl.Type == proto.PayloadData {
			l := len(pl.Data)
			pl.Data = pl.Data[:l+1]
			copy(pl.Data[1:], pl.Data)
			pl.Data[0] = pl.Type
		} else {
			pl.Data = append(pl.Data[:0], pl.Type)
		}

		bytesSent, err = conn.Write(pl.Data)
		if err != nil {
			base.Error("dtls payloadOut to server error:", err)
			return
		}
		cSess.Stat.BytesSent.Add(uint64(bytesSent))

		putPayloadBuffer(pl)
	}
}

type SessionStore struct {
	sess dtls.Session
}

func (store *SessionStore) Set([]byte, dtls.Session) error {
	return nil
}

func (store *SessionStore) Get([]byte) (dtls.Session, error) {
	return store.sess, nil
}

func (store *SessionStore) Del([]byte) error {
	return nil
}
