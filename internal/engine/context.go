package engine

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"

	engineconfig "github.com/WarrDoge/tuncat/internal/engine/config"
	enginesession "github.com/WarrDoge/tuncat/internal/engine/session"
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

type Context struct {
	Cfg            *engineconfig.ClientConfig
	LocalInterface *engineconfig.Interface
	Logger         *engineconfig.Logger
	Profile        *Profile
	Session        *enginesession.Session
	Auth           *AuthState
	RoutingState   any
	TLSCert        *tls.Certificate
	RootCAs        *x509.CertPool
}

func NewContext() *Context {
	cfg := engineconfig.NewClientConfig()
	return &Context{
		Cfg:            cfg,
		LocalInterface: engineconfig.NewInterface(),
		Logger:         engineconfig.NewLogger(cfg),
		Profile:        NewProfile(),
		Session:        &enginesession.Session{},
		Auth:           NewAuthState(),
	}
}
