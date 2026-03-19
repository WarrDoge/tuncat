package app

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sslcon/auth"
	"sslcon/base"
	"sslcon/lib"
	"sslcon/rpc"
)

func runVPNCore(cfg *Config, pfxCreds *PFXCredentials, verbose bool, onConnected func()) (int, error) {
	target, err := splitServerForVPNCore(cfg.Server)
	if err != nil {
		return 1, err
	}

	vpnCtx := lib.NewVPNContext()
	applyVPNCoreConfig(vpnCtx, cfg, verbose)
	if verbose && vpnCtx.Cfg.DebugLogPath != "" {
		log.Printf("Verbose VPN core logs are written to %s", vpnCtx.Cfg.DebugLogPath)
	}
	applyVPNCoreProfile(vpnCtx, cfg, target)
	auth.SetTLSCredentials(vpnCtx, pfxCreds.Certificate, pfxCreds.RootCAs)
	defer auth.ClearTLSCredentials(vpnCtx)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	log.Printf("Connecting to %s as %s...", target.Host, cfg.Username)
	if err := rpc.Connect(vpnCtx); err != nil {
		return 1, fmt.Errorf("error starting VPN core: %w", err)
	}

	if cfg.VerifyURL != "" {
		dnsServers := []string(nil)
		if vpnCtx.Session != nil && vpnCtx.Session.CSess != nil {
			dnsServers = append(dnsServers, vpnCtx.Session.CSess.DNS...)
		}
		verification := verifyEndpoint(cfg.VerifyURL, dnsServers)
		log.Printf(
			"verify_url result: host=%s dns_servers=%v addresses=%v resolved=%t http_status=%d attempts=%d duration=%s error=%q",
			verification.Host,
			verification.DNSServers,
			verification.Addresses,
			verification.Resolved,
			verification.HTTPStatus,
			verification.Attempts,
			verification.Duration,
			verification.Error,
		)
		if verification.Error != "" || !verification.HTTPOK() {
			rpc.DisConnect(vpnCtx)
			select {
			case <-vpnCtx.Session.CloseChan:
			case <-time.After(gracefulTimeout):
			}
			if verification.Error != "" {
				return 1, fmt.Errorf("verify_url failed: %s", verification.Error)
			}
			return 1, fmt.Errorf("verify_url failed with HTTP status %d", verification.HTTPStatus)
		}
	}

	if onConnected != nil {
		onConnected()
	}
	log.Println("VPN connected. Press Ctrl+C to disconnect.")

	doneChan := vpnCtx.Session.CloseChan
	if doneChan == nil {
		return 1, fmt.Errorf("VPN core did not expose a session channel")
	}

	select {
	case <-doneChan:
		if vpnCtx.Session.ActiveClose {
			log.Println("VPN disconnected.")
			return 0, nil
		}
		log.Println("VPN session closed by peer.")
		return 1, nil
	case sig := <-sigChan:
		log.Printf("Received %v, disconnecting...", sig)
		rpc.DisConnect(vpnCtx)
		select {
		case <-doneChan:
		case <-time.After(gracefulTimeout):
			return exitSignal, fmt.Errorf("timeout waiting for VPN core disconnect")
		}
		return exitSignal, nil
	}
}

func applyVPNCoreConfig(vpnCtx *lib.VPNContext, cfg *Config, verbose bool) {
	vpnCtx.Cfg.LogLevel = "Info"
	if verbose {
		vpnCtx.Cfg.LogLevel = "Debug"
	}
	vpnCtx.Cfg.LogPath = ""
	vpnCtx.Cfg.DebugLogPath = ""
	vpnCtx.Cfg.InsecureSkipVerify = false
	vpnCtx.Cfg.CiscoCompat = true
	vpnCtx.Cfg.NoDTLS = false
	vpnCtx.Cfg.AgentVersion = "v9.12-1build5"
	vpnCtx.Cfg.AgentName = "AnyConnect"
	if strings.TrimSpace(cfg.UserAgent) != "" && !strings.EqualFold(strings.TrimSpace(cfg.UserAgent), "AnyConnect") {
		vpnCtx.Cfg.CiscoCompat = false
		vpnCtx.Cfg.AgentName = strings.TrimSpace(cfg.UserAgent)
	}
	vpnCtx.Cfg.BaseMTU = cfg.BaseMTU
	vpnCtx.Cfg.SplitRoutes = append([]string(nil), cfg.SplitRoutes...)
	vpnCtx.Cfg.DNSDomains = append([]string(nil), cfg.DNSDomains...)
	vpnCtx.Cfg.ServerCertPin = strings.TrimSpace(cfg.ServerCert)
	if strings.TrimSpace(cfg.RPCAddr) != "" {
		vpnCtx.Cfg.RPCAddr = strings.TrimSpace(cfg.RPCAddr)
	}
	if strings.TrimSpace(cfg.DebugLogPath) != "" {
		vpnCtx.Cfg.DebugLogPath = strings.TrimSpace(cfg.DebugLogPath)
	} else if verbose {
		vpnCtx.Cfg.DebugLogPath = filepath.Join(os.TempDir(), "tuncat-debug.log")
	}
	vpnCtx.Logger = base.InitLog(vpnCtx.Cfg)
}

func applyVPNCoreProfile(vpnCtx *lib.VPNContext, cfg *Config, target serverTarget) {
	vpnCtx.Profile.Host = target.Host
	vpnCtx.Profile.Username = cfg.Username
	vpnCtx.Profile.Password = cfg.Password
	vpnCtx.Profile.Group = target.Group
	vpnCtx.Profile.BasePath = target.BasePath
	vpnCtx.Profile.SecretKey = ""
	vpnCtx.Profile.Initialized = false
}

type serverTarget struct {
	Host     string
	Group    string
	BasePath string
}

func splitServerForVPNCore(raw string) (serverTarget, error) {
	server := strings.TrimSpace(raw)
	if server == "" {
		return serverTarget{}, fmt.Errorf("server is empty")
	}
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil {
		return serverTarget{}, fmt.Errorf("invalid server: %w", err)
	}

	host := strings.TrimSpace(u.Host)
	group := ""
	basePath := strings.TrimSpace(u.EscapedPath())
	if basePath == "" {
		basePath = "/"
	} else {
		basePath = "/" + strings.Trim(path.Clean(basePath), "/")
		if basePath == "/." {
			basePath = "/"
		}
		group = strings.Trim(basePath, "/")
	}
	if q := strings.TrimSpace(u.RawQuery); q != "" {
		basePath = basePath + "?" + q
	}
	if host == "" {
		return serverTarget{}, fmt.Errorf("server host is empty")
	}

	return serverTarget{Host: host, Group: group, BasePath: basePath}, nil
}
