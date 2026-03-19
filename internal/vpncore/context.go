package vpncore

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"

	"tuncat/internal/vpncore/base"
	"tuncat/internal/vpncore/session"
)

type Profile struct {
	Host      string `json:"host"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Group     string `json:"group"`
	SecretKey string `json:"secret"`

	Initialized bool
	AppVersion  string // for report to server in xml

	HostWithPort string
	Scheme       string
	BasePath     string
	AuthPath     string

	TunnelGroup string
	AuthMethod  string
	GroupAlias  string
	ConfigHash  string
	GroupAccess string
	DeviceID    string
}

func NewProfile() *Profile {
	return &Profile{
		Scheme:   "https://",
		BasePath: "/",
	}
}

type AuthState struct {
	Conn         *tls.Conn
	BufR         *bufio.Reader
	WebVPNCookie string
	ReqHeaders   map[string]string
}

func NewAuthState() *AuthState {
	return &AuthState{ReqHeaders: make(map[string]string)}
}

type VPNContext struct {
	Cfg            *base.ClientConfig
	LocalInterface *base.Interface
	Logger         *base.Logger
	Profile        *Profile
	Session        *session.Session
	Auth           *AuthState
	RoutingState   any
	TLSCert        *tls.Certificate
	RootCAs        *x509.CertPool
}

func NewVPNContext() *VPNContext {
	cfg := base.NewClientConfig()
	return &VPNContext{
		Cfg:            cfg,
		LocalInterface: base.NewInterface(),
		Logger:         base.NewLogger(cfg),
		Profile:        NewProfile(),
		Session:        &session.Session{},
		Auth:           NewAuthState(),
	}
}
