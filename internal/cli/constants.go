package cli

import (
	"fmt"
	"time"
)

const (
	Version = "0.2.1"

	obscureKey    = "\x9c\x93\x5b\x48\x73\x0a\x55\x4d\x6b\xe0\x76\x3f\x1a\xc4\xd8\x2e"
	obscurePrefix = "obscured:"

	gracefulTimeout = 5 * time.Second
	exitSignal      = 130

	defaultRetryBackoff = 5 * time.Second
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

	MaxRetries   int    `yaml:"max_retries"`
	RetryBackoff string `yaml:"retry_backoff"`
}

func defaults() *Config {
	return &Config{
		Protocol:  "anyconnect",
		UserAgent: "AnyConnect",
		BaseMTU:   1200,

		MaxRetries:   -1,   // infinite by default
		RetryBackoff: "5s", // 5 second default backoff
	}
}

func parseRetryBackoff(s string) (time.Duration, error) {
	if s == "" {
		return defaultRetryBackoff, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("cannot parse %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("retry_backoff must be positive, got %s", d)
	}
	return d, nil
}
