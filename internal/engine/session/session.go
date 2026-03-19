package session

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	uatomic "go.uber.org/atomic"
	engineconfig "tuncat/internal/engine/config"
	"tuncat/internal/engine/netutil"
	"tuncat/internal/engine/protocol"
)

type Session struct {
	SessionToken    string
	PreMasterSecret []byte

	ActiveClose bool
	closeOnce   sync.Once
	CloseChan   chan struct{}
	CSess       *ConnSession
}

type stat struct {
	BytesSent     atomic.Uint64
	BytesReceived atomic.Uint64
}

func (s *stat) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		BytesSent     uint64 `json:"bytesSent"`
		BytesReceived uint64 `json:"bytesReceived"`
	}{
		BytesSent:     s.BytesSent.Load(),
		BytesReceived: s.BytesReceived.Load(),
	})
}

// ConnSession used for both TLS and DTLS
type ConnSession struct {
	Sess *Session `json:"-"`

	ServerAddress string
	LocalAddress  string
	Hostname      string
	TunName       string
	VPNAddress    string // The IPv4 address of the client
	VPNMask       string // IPv4 netmask
	DNS           []string
	MTU           int
	SplitInclude  []string
	SplitExclude  []string

	DynamicSplitTunneling       bool
	DynamicSplitIncludeDomains  []string
	DynamicSplitIncludeResolved sync.Map // https://github.com/golang/go/issues/31136
	DynamicSplitExcludeDomains  []string
	DynamicSplitExcludeResolved sync.Map

	TLSCipherSuite    string
	TLSDpdTime        int // https://datatracker.ietf.org/doc/html/rfc3706
	TLSKeepaliveTime  int
	DTLSPort          string
	DTLSDpdTime       int
	DTLSKeepaliveTime int
	DTLSId            string `json:"-"` // used by the server to associate the DTLS channel with the CSTP channel
	DTLSCipherSuite   string
	Stat              *stat

	closeOnce      sync.Once              `json:"-"`
	CloseChan      chan struct{}          `json:"-"`
	PayloadIn      chan *protocol.Payload `json:"-"`
	PayloadOutTLS  chan *protocol.Payload `json:"-"`
	PayloadOutDTLS chan *protocol.Payload `json:"-"`

	DtlsConnected *uatomic.Bool
	DtlsSetupChan chan struct{} `json:"-"`
	DSess         *DtlsSession  `json:"-"`

	ResetTLSReadDead  *uatomic.Bool `json:"-"`
	ResetDTLSReadDead *uatomic.Bool `json:"-"`
}

type DtlsSession struct {
	closeOnce sync.Once
	CloseChan chan struct{}
	cSess     *ConnSession
}

func (sess *Session) NewConnSession(header *http.Header, localAddress string, noDTLS bool) *ConnSession {
	cSess := &ConnSession{
		Sess:         sess,
		LocalAddress: localAddress,
		Stat:         &stat{},
		closeOnce:    sync.Once{},
		CloseChan:    make(chan struct{}),
		// Closed after DTLS setup succeeds or fails.
		DtlsSetupChan:     make(chan struct{}),
		PayloadIn:         make(chan *protocol.Payload, 64),
		PayloadOutTLS:     make(chan *protocol.Payload, 64),
		PayloadOutDTLS:    make(chan *protocol.Payload, 64),
		DtlsConnected:     uatomic.NewBool(false),
		ResetTLSReadDead:  uatomic.NewBool(true),
		ResetDTLSReadDead: uatomic.NewBool(true),
		DSess: &DtlsSession{
			closeOnce: sync.Once{},
			CloseChan: make(chan struct{}),
		},
	}
	cSess.DSess.cSess = cSess
	sess.CSess = cSess

	sess.ActiveClose = false
	sess.CloseChan = make(chan struct{})

	cSess.VPNAddress = header.Get("X-CSTP-Address")
	cSess.VPNMask = header.Get("X-CSTP-Netmask")
	cSess.MTU, _ = strconv.Atoi(header.Get("X-CSTP-MTU"))
	cSess.DNS = header.Values("X-CSTP-DNS")
	cSess.SplitInclude = header.Values("X-CSTP-Split-Include")
	cSess.SplitExclude = header.Values("X-CSTP-Split-Exclude")

	cSess.TLSDpdTime, _ = strconv.Atoi(header.Get("X-CSTP-DPD"))
	cSess.TLSKeepaliveTime, _ = strconv.Atoi(header.Get("X-CSTP-Keepalive"))
	// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-02#section-2.1.5.1
	cSess.DTLSId = header.Get("X-DTLS-Session-ID")
	if cSess.DTLSId == "" {
		cSess.DTLSId = header.Get("X-DTLS-App-ID")
	}
	cSess.DTLSPort = header.Get("X-DTLS-Port")
	cSess.DTLSDpdTime, _ = strconv.Atoi(header.Get("X-DTLS-DPD"))
	cSess.DTLSKeepaliveTime, _ = strconv.Atoi(header.Get("X-DTLS-Keepalive"))
	if noDTLS {
		cSess.DTLSCipherSuite = "Unknown"
	} else {
		cSess.DTLSCipherSuite = header.Get("X-DTLS12-CipherSuite")
	}

	// Parse optional post-auth XML for dynamic split-domain directives.
	postAuth := header.Get("X-CSTP-Post-Auth-XML")
	if postAuth != "" {
		dtd := protocol.DTD{}
		err := xml.Unmarshal([]byte(postAuth), &dtd)
		if err == nil {
			if dtd.Config.Opaque.CustomAttr.DynamicSplitIncludeDomains != "" {
				cSess.DynamicSplitIncludeDomains = strings.Split(dtd.Config.Opaque.CustomAttr.DynamicSplitIncludeDomains, ",")
				cSess.DynamicSplitTunneling = true
			} else if dtd.Config.Opaque.CustomAttr.DynamicSplitExcludeDomains != "" {
				cSess.DynamicSplitExcludeDomains = strings.Split(dtd.Config.Opaque.CustomAttr.DynamicSplitExcludeDomains, ",")
				cSess.DynamicSplitTunneling = true
			}

		}
	}

	return cSess
}

func (cSess *ConnSession) DPDTimer() {
	go func() {
		defer func() {
			engineconfig.Info("dead peer detection timer exit")
		}()
		engineconfig.Debug("TLSDpdTime:", cSess.TLSDpdTime, "TLSKeepaliveTime", cSess.TLSKeepaliveTime,
			"DTLSDpdTime", cSess.DTLSDpdTime, "DTLSKeepaliveTime", cSess.DTLSKeepaliveTime)
		// Trigger probes slightly before server timers to avoid idle disconnect.
		dpdTime := netutil.Min(cSess.TLSDpdTime, cSess.DTLSDpdTime) - 5
		if dpdTime < 10 {
			dpdTime = 10
		}
		ticker := time.NewTicker(time.Duration(dpdTime) * time.Second)

		tlsDpd := protocol.Payload{
			Type: protocol.PayloadDPDReq,
			Data: make([]byte, 0, 8),
		}
		dtlsDpd := protocol.Payload{
			Type: protocol.PayloadDPDReq,
			Data: make([]byte, 0, 1),
		}

		for {
			select {
			case <-ticker.C:
				select {
				case cSess.PayloadOutTLS <- &tlsDpd:
				default:
				}
				if cSess.DtlsConnected.Load() {
					select {
					case cSess.PayloadOutDTLS <- &dtlsDpd:
					default:
					}
				}
			case <-cSess.CloseChan:
				ticker.Stop()
				return
			}
		}
	}()
}

func (cSess *ConnSession) ReadDeadTimer() {
	go func() {
		defer func() {
			engineconfig.Info("read dead timer exit")
		}()
		ticker := time.NewTicker(4 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cSess.ResetTLSReadDead.Store(true)
				cSess.ResetDTLSReadDead.Store(true)
			case <-cSess.CloseChan:
				return
			}
		}
	}()
}

func (cSess *ConnSession) Close() {
	cSess.closeOnce.Do(func() {
		if cSess.DtlsConnected.Load() {
			cSess.DSess.Close()
		}
		close(cSess.CloseChan)
		cSess.Sess.CSess = nil

		cSess.Sess.closeOnce.Do(func() {
			close(cSess.Sess.CloseChan)
		})
	})
}

func (dSess *DtlsSession) Close() {
	dSess.closeOnce.Do(func() {
		close(dSess.CloseChan)
		if dSess.cSess != nil {
			dSess.cSess.DtlsConnected.Store(false)
			dSess.cSess.DTLSCipherSuite = ""
		}
	})
}
