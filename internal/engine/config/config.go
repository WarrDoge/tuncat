package config

//
// Per-consumer field requirements
//
// Each field below documents which engine component reads it and what shape
// the consumer expects. There is no central Validate() — ApplyDefaults
// produces sane defaults and each consumer enforces its own constraints at
// the point of use. Keep this section in sync when adding or changing fields.
//
// Consumers:
//
//   LogLevel  — log.go (NewLogger→logLevel2Int), auth.go & tunnel.go check
//               for "Debug" at call sites. ApplyDefaults: "Debug" if empty.
//               Unknown values default to Info level via logLevel2Int.
//
//   LogPath   — log.go (NewLogger→logWriter). Empty → stdout.
//
//   DebugLogPath — log.go. Empty → same as normal log.
//
//   RPCAddr    — control/rpc.go (normalizeRPCAddr). ApplyDefaults: "127.0.0.1:6210".
//               normalizeRPCAddr accepts ":port" or bare port number, and
//               enforces loopback-only host. Empty → RPC server disabled.
//
//   InsecureSkipVerify — auth.go (InitAuth→tls.Config). ApplyDefaults: false.
//
//   CiscoCompat — auth.go & tunnel.go (SetCommonHeader + User-Agent override).
//               ApplyDefaults: true.
//
//   NoDTLS     — tunnel.go (spawns DTLS channel when false + port available).
//               Default: false (zero value).
//
//   AgentName  — auth.go & tunnel.go (SetCommonHeader). ApplyDefaults: "AnyConnect".
//
//   AgentVersion — auth.go & tunnel.go (SetCommonHeader + profile version).
//               ApplyDefaults: "4.10.07062".
//
//   BaseMTU    — tunnel.go (initTunnel→MTU header). ApplyDefaults: 1200 if 0.
//               Must be > 0. Auth layer does not enforce range — invalid values
//               fail at the VPN gateway.
//
//   SplitRoutes — network/vpnc_{linux,darwin,windows}.go (route inclusion).
//               Each OS consumer checks len > 0 and passes CIDRs to OS routing.
//               No consumer parses CIDRs; invalid CIDRs pass silently to OS.
//
//   DNSDomains — network/common.go (NormalizeDNSDomains). Drops empties,
//               trims whitespace, lowercases. Empty slice is valid.
//
//   ServerCertPin — internal detail, consumed by applyTLSOptions in auth.
//

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
