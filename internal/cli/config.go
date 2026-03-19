package cli

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
	"github.com/WarrDoge/tuncat/internal/engine/network"
)

func findConfigFile(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}
	candidates := []string{
		filepath.Join("tuncat", "config.yaml"),
		filepath.Join(".tuncat", "config.yaml"),
		"config.yaml", // legacy fallback
	}

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates,
			filepath.Join(home, "tuncat", "config.yaml"),
			filepath.Join(home, ".tuncat", "config.yaml"),
		)
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func loadConfig(path string) (*Config, error) {
	cfg := defaults()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.PfxPath != "" && !filepath.IsAbs(cfg.PfxPath) {
		cfg.PfxPath = filepath.Join(filepath.Dir(path), cfg.PfxPath)
	}
	return cfg, nil
}

func normalizeConfig(cfg *Config) {
	cfg.Server = strings.TrimSpace(cfg.Server)
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.PfxPath = strings.TrimSpace(cfg.PfxPath)
	cfg.Protocol = strings.TrimSpace(cfg.Protocol)
	cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	cfg.ServerCert = strings.TrimSpace(cfg.ServerCert)
	cfg.VerifyURL = strings.TrimSpace(cfg.VerifyURL)
	cfg.RPCAddr = strings.TrimSpace(cfg.RPCAddr)
	cfg.DebugLogPath = strings.TrimSpace(cfg.DebugLogPath)

	cfg.DNSDomains = network.NormalizeDNSDomains(cfg.DNSDomains)
}

func validateConfig(cfg *Config) []string {
	var errs []string
	if cfg.Server == "" {
		errs = append(errs, "missing required config field: server")
	}
	if cfg.Username == "" {
		errs = append(errs, "missing required config field: username")
	}
	if cfg.PfxPath == "" {
		errs = append(errs, "missing required config field: pfx_path")
	} else if _, err := os.Stat(cfg.PfxPath); err != nil {
		errs = append(errs, fmt.Sprintf("PFX file not found: %s", cfg.PfxPath))
	}
	if cfg.BaseMTU < 576 || cfg.BaseMTU > 20000 {
		errs = append(errs, fmt.Sprintf("base_mtu out of range (%d); expected 576..20000", cfg.BaseMTU))
	}
	for _, r := range cfg.SplitRoutes {
		if _, _, err := parseSplitRoute(r); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, d := range cfg.DNSDomains {
		if strings.ContainsAny(d, " \t\n") {
			errs = append(errs, fmt.Sprintf("invalid dns_domain %q: whitespace not allowed", d))
		}
	}
	if cfg.VerifyURL != "" {
		u, err := url.Parse(cfg.VerifyURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("invalid verify_url %q: %v", cfg.VerifyURL, err))
		} else if u.Hostname() == "" {
			errs = append(errs, fmt.Sprintf("invalid verify_url %q: host is empty", cfg.VerifyURL))
		} else if u.Scheme != "http" && u.Scheme != "https" {
			errs = append(errs, fmt.Sprintf("invalid verify_url %q: scheme must be http or https", cfg.VerifyURL))
		}
	}
	if cfg.RPCAddr != "" {
		host, _, err := net.SplitHostPort(cfg.RPCAddr)
		if err != nil {
			errS := cfg.RPCAddr
			if strings.HasPrefix(errS, ":") {
				host = "127.0.0.1"
			} else {
				errs = append(errs, fmt.Sprintf("invalid rpc_addr %q: %v", cfg.RPCAddr, err))
			}
		}
		if host != "" && host != "127.0.0.1" && host != "localhost" && host != "::1" {
			errs = append(errs, fmt.Sprintf("invalid rpc_addr host %q: only localhost/loopback is allowed", host))
		}
	}
	return errs
}

func preflightChecks(_ *Config) []string {
	var errs []string

	switch runtime.GOOS {
	case "linux":
		if os.Geteuid() != 0 {
			errs = append(errs, "must run as root (use: sudo tuncat)")
		}
		if _, err := os.Stat("/dev/net/tun"); err != nil {
			errs = append(errs, "TUN device is unavailable: /dev/net/tun")
		}
	case "darwin":
		if os.Geteuid() != 0 {
			errs = append(errs, "must run as root (use: sudo tuncat)")
		}
	case "windows":
		// no static preflight checks; permission errors surface on connect
	default:
		errs = append(errs, fmt.Sprintf("unsupported platform: %s", runtime.GOOS))
	}

	return errs
}

func parseSplitRoute(cidr string) (addr string, masklen int, err error) {
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
