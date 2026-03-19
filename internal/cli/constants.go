package cli

import "time"

const (
	Version = "0.1.2"

	obscureKey    = "\x9c\x93\x5b\x48\x73\x0a\x55\x4d\x6b\xe0\x76\x3f\x1a\xc4\xd8\x2e"
	obscurePrefix = "obscured:"

	gracefulTimeout = 5 * time.Second
	exitSignal      = 130
)

type Config struct {
	Server       string   `yaml:"server"`
	Username     string   `yaml:"username"`
	Password     string   `yaml:"password"`
	PfxPath      string   `yaml:"pfx_path"`
	PfxPassword  string   `yaml:"pfx_password"`
	Protocol     string   `yaml:"protocol"`
	UserAgent    string   `yaml:"user_agent"`
	BaseMTU      int      `yaml:"base_mtu"`
	SplitRoutes  []string `yaml:"split_routes"`
	DNSDomains   []string `yaml:"dns_domains"`
	VerifyURL    string   `yaml:"verify_url"`
	RPCAddr      string   `yaml:"rpc_addr"`
	DebugLogPath string   `yaml:"debug_log_path"`

	ServerCert string `yaml:"server_cert"`
}

func defaults() *Config {
	return &Config{
		Protocol:  "anyconnect",
		UserAgent: "AnyConnect",
		BaseMTU:   1200,
	}
}
