package config

import (
	"fmt"
	"net"
	"strings"
)

// knownLevels maps the set of valid log level names for validation.
var knownLevels = map[string]bool{
	"debug": true,
	"info":  true,
	"warn":  true,
	"error": true,
	"fatal": true,
}

type ClientConfig struct {
	LogLevel           string `json:"log_level"`
	LogPath            string `json:"log_path"`
	DebugLogPath       string `json:"debug_log_path"`
	RPCAddr            string `json:"rpc_addr"`
	InsecureSkipVerify bool   `json:"skip_verify"`
	CiscoCompat        bool   `json:"cisco_compat"`
	NoDTLS             bool   `json:"no_dtls"`
	AgentName          string `json:"agent_name"`
	AgentVersion       string `json:"agent_version"`
	BaseMTU            int    `json:"base_mtu"`

	SplitRoutes []string `json:"split_routes"`
	DNSDomains  []string `json:"dns_domains"`

	ServerCertPin string `json:"server_cert"`
}

// Validate checks the config and returns a slice of errors for every field
// that is invalid. An empty slice means the config is valid.
// Fields that ApplyDefaults fills (empty RPCAddr, empty LogLevel) are allowed;
// they are not errors here — call ApplyDefaults before or after Validate
// depending on whether the caller wants to fail early or fill defaults first.
func (c *ClientConfig) Validate() []error {
	var errs []error

	if c.BaseMTU != 0 && (c.BaseMTU < 576 || c.BaseMTU > 20000) {
		errs = append(errs, fmt.Errorf(
			"base_mtu out of range (%d); expected 576..20000 (0 means default)", c.BaseMTU))
	}

	for i, r := range c.SplitRoutes {
		if _, _, err := parseCIDR(r); err != nil {
			errs = append(errs, fmt.Errorf("split_routes[%d]: %w", i, err))
		}
	}

	if c.RPCAddr != "" {
		_, _, err := net.SplitHostPort(c.RPCAddr)
		if err != nil {
			errs = append(errs, fmt.Errorf("rpc_addr %q: missing or invalid port", c.RPCAddr))
		}
	}

	if c.LogLevel != "" {
		if !knownLevels[strings.ToLower(c.LogLevel)] {
			errs = append(errs, fmt.Errorf(
				"log_level %q is not a known level; expected one of: Debug, Info, Warn, Error, Fatal",
				c.LogLevel))
		}
	}

	return errs
}

func parseCIDR(cidr string) (string, int, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if ipnet.IP.To4() == nil {
		return "", 0, fmt.Errorf("IPv6 CIDR %q not supported", cidr)
	}
	ones, _ := ipnet.Mask.Size()
	return ipnet.IP.String(), ones, nil
}

type Interface struct {
	Name    string `json:"name"`
	Ip4     string `json:"ip4"`
	Mac     string `json:"mac"`
	Gateway string `json:"gateway"`
}

func NewClientConfig() *ClientConfig {
	cfg := &ClientConfig{}
	ApplyDefaults(cfg)
	return cfg
}

func NewInterface() *Interface {
	return &Interface{}
}

func ApplyDefaults(cfg *ClientConfig) {
	if cfg == nil {
		return
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "Debug"
	}
	if cfg.RPCAddr == "" {
		cfg.RPCAddr = "127.0.0.1:6210"
	}
	cfg.InsecureSkipVerify = false
	cfg.CiscoCompat = true
	if cfg.AgentName == "" {
		cfg.AgentName = "AnyConnect"
	}
	if cfg.AgentVersion == "" {
		cfg.AgentVersion = "4.10.07062"
	}
	if cfg.BaseMTU == 0 {
		cfg.BaseMTU = 1200
	}
}
