package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestClientConfigJSONFieldNames pins the JSON wire contract for ClientConfig.
// The RPC CONFIG method (internal/engine/control/rpc.go) unmarshals raw JSON
// params into this struct, and the CLI config (internal/cli/config.go) sends
// snake_case YAML keys. These must agree, else config silently fails to land.
func TestClientConfigJSONFieldNames(t *testing.T) {
	cfg := ClientConfig{
		LogLevel:           "Debug",
		LogPath:            "/var/log",
		DebugLogPath:       "/var/log/debug.log",
		RPCAddr:            "127.0.0.1:6210",
		InsecureSkipVerify: true,
		CiscoCompat:        true,
		NoDTLS:             true,
		AgentName:          "AnyConnect",
		AgentVersion:       "4.10.07062",
		BaseMTU:            1400,
		SplitRoutes:        []string{"10.0.0.0/8", "192.168.0.0/16"},
		DNSDomains:         []string{"corp.example.com"},
		ServerCertPin:      "sha256/AAA",
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal to map: %v", err)
	}
	want := []string{
		"log_level", "log_path", "debug_log_path", "rpc_addr", "skip_verify",
		"cisco_compat", "no_dtls", "agent_name", "agent_version", "base_mtu",
		"split_routes", "dns_domains", "server_cert",
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("ClientConfig JSON field %q missing from marshaled output (keys=%v)", k, keys(m))
		}
	}
}

func keys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestClientConfigJSONRoundTrip(t *testing.T) {
	in := ClientConfig{
		LogLevel:           "Warn",
		LogPath:            "/tmp/logs",
		DebugLogPath:       "/tmp/logs/debug.log",
		RPCAddr:            "127.0.0.1:9999",
		InsecureSkipVerify: true,
		CiscoCompat:        true,
		NoDTLS:             true,
		AgentName:          "CustomAgent",
		AgentVersion:       "9.9.9",
		BaseMTU:            9000,
		SplitRoutes:        []string{"10.1.1.0/24"},
		DNSDomains:         []string{"a.example", "b.example"},
		ServerCertPin:      "sha256/BBBB",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out ClientConfig
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

func TestClientConfigUnmarshalRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"truncated object":  `{"base_mtu": `,
		"bad base_mtu type": `{"base_mtu": "not-an-int"}`,
		"bad list type":     `{"split_routes": 42}`,
		"garbage":           `not json at all`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			var cfg ClientConfig
			if err := json.Unmarshal([]byte(in), &cfg); err == nil {
				t.Fatalf("expected error for input %q, got none", in)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := NewClientConfig()
	want := ClientConfig{
		LogLevel:           "Debug",
		LogPath:            "",
		DebugLogPath:       "",
		RPCAddr:            "127.0.0.1:6210",
		InsecureSkipVerify: false,
		CiscoCompat:        true,
		NoDTLS:             false,
		AgentName:          "AnyConnect",
		AgentVersion:       "4.10.07062",
		BaseMTU:            1200,
	}
	if !reflect.DeepEqual(*cfg, want) {
		t.Fatalf("defaults mismatch:\n got=%+v\nwant=%+v", *cfg, want)
	}
}

func TestApplyDefaultsPreservesNonZero(t *testing.T) {
	cfg := &ClientConfig{
		LogLevel:     "Error",
		RPCAddr:      "10.0.0.1:1234",
		AgentName:    "Custom",
		AgentVersion: "1.0.0",
		BaseMTU:      9000,
		SplitRoutes:  []string{"10.0.0.0/8"},
		DNSDomains:   []string{"x.example"},
	}
	ApplyDefaults(cfg)
	if cfg.LogLevel != "Error" {
		t.Errorf("LogLevel overwritten: %q", cfg.LogLevel)
	}
	if cfg.RPCAddr != "10.0.0.1:1234" {
		t.Errorf("RPCAddr overwritten: %q", cfg.RPCAddr)
	}
	if cfg.AgentName != "Custom" || cfg.AgentVersion != "1.0.0" {
		t.Errorf("agent identity overwritten: %q %q", cfg.AgentName, cfg.AgentVersion)
	}
	if cfg.BaseMTU != 9000 {
		t.Errorf("BaseMTU overwritten: %d", cfg.BaseMTU)
	}
	if !cfg.CiscoCompat {
		t.Errorf("CiscoCompat default true not applied")
	}
}

func TestApplyDefaultsNil(t *testing.T) {
	// Must not panic and must be a no-op.
	ApplyDefaults(nil)
}

// TestBaseMTUDefaultsOnZero covers the engine-config side of base_mtu: a zero
// value means "unset" and defaults to 1200; any non-zero value is preserved.
// The 576..20000 range rejection lives in cli.validateConfig (centralized
// validation chokepoint), not here.
func TestBaseMTUDefaultsOnZero(t *testing.T) {
	cfg := &ClientConfig{}
	ApplyDefaults(cfg)
	if cfg.BaseMTU != 1200 {
		t.Fatalf("zero base_mtu defaulted to %d, want 1200", cfg.BaseMTU)
	}

	cfg = &ClientConfig{BaseMTU: 1400}
	ApplyDefaults(cfg)
	if cfg.BaseMTU != 1400 {
		t.Fatalf("non-zero base_mtu preserved as %d, want 1400", cfg.BaseMTU)
	}
}

func TestSplitRoutesAndDNSDomainsShapes(t *testing.T) {
	// Empty lists parse to nil, single and multi-element lists parse in order.
	in := `{"split_routes":["10.0.0.0/8"],"dns_domains":["a.example","b.example"]}`
	var cfg ClientConfig
	if err := json.Unmarshal([]byte(in), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.SplitRoutes) != 1 || cfg.SplitRoutes[0] != "10.0.0.0/8" {
		t.Errorf("split_routes = %v, want [10.0.0.0/8]", cfg.SplitRoutes)
	}
	if len(cfg.DNSDomains) != 2 || cfg.DNSDomains[0] != "a.example" || cfg.DNSDomains[1] != "b.example" {
		t.Errorf("dns_domains = %v, want [a.example b.example]", cfg.DNSDomains)
	}

	var empty ClientConfig
	if err := json.Unmarshal([]byte(`{"split_routes":[],"dns_domains":[]}`), &empty); err != nil {
		t.Fatalf("unmarshal empty lists: %v", err)
	}
	if len(empty.SplitRoutes) != 0 || empty.SplitRoutes == nil {
		t.Errorf("explicit [] split_routes should unmarshal to empty non-nil slice, got %#v", empty.SplitRoutes)
	}
	if len(empty.DNSDomains) != 0 || empty.DNSDomains == nil {
		t.Errorf("explicit [] dns_domains should unmarshal to empty non-nil slice, got %#v", empty.DNSDomains)
	}

	// Absent keys leave the slices nil — distinct from explicit empty lists.
	var absent ClientConfig
	if err := json.Unmarshal([]byte(`{}`), &absent); err != nil {
		t.Fatalf("unmarshal absent lists: %v", err)
	}
	if absent.SplitRoutes != nil || absent.DNSDomains != nil {
		t.Errorf("absent keys should leave slices nil, got split_routes=%#v dns_domains=%#v", absent.SplitRoutes, absent.DNSDomains)
	}
}

// TestInterfaceJSON pins the wire contract for the RPC INTERFACE method.
func TestInterfaceJSON(t *testing.T) {
	in := Interface{Name: "tun0", Ip4: "10.0.0.2", Mac: "aa:bb:cc:dd:ee:ff", Gateway: "10.0.0.1"}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	for _, k := range []string{"name", "ip4", "mac", "gateway"} {
		if _, ok := m[k]; !ok {
			t.Errorf("Interface JSON field %q missing", k)
		}
	}
	var out Interface
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

func TestNewInterface(t *testing.T) {
	if got := NewInterface(); got == nil || *got != (Interface{}) {
		t.Fatalf("NewInterface() = %+v, want empty Interface", got)
	}
}

// log.go

func TestLogLevel2Int(t *testing.T) {
	cases := map[string]int{
		"Debug":   _Debug,
		"debug":   _Debug,
		"DEBUG":   _Debug,
		"Info":    _Info,
		"Warn":    _Warn,
		"warn":    _Warn,
		"Error":   _Error,
		"Fatal":   _Fatal,
		"":        _Info,
		"garbage": _Info,
		"INFO":    _Info,
	}
	for level, want := range cases {
		if got := logLevel2Int(level); got != want {
			t.Errorf("logLevel2Int(%q) = %d, want %d", level, got, want)
		}
	}
}

func TestNewLoggerDefaultsToStdout(t *testing.T) {
	cfg := &ClientConfig{LogLevel: "Info"}
	lg := NewLogger(cfg)
	if lg == nil {
		t.Fatal("NewLogger returned nil")
	}
	if lg.normalWriter == nil || !lg.normalWriter.UseStdout {
		t.Errorf("empty LogPath should default to stdout writer, got %+v", lg.normalWriter)
	}
	if lg.normalWriter.File != os.Stdout {
		t.Errorf("normal writer file = %v, want os.Stdout", lg.normalWriter.File)
	}
	// No debug log path: debug writer aliases the normal (stdout) writer.
	if lg.debugWriter != lg.normalWriter {
		t.Errorf("debug writer should alias normal writer when DebugLogPath empty")
	}
}

func TestNewLoggerWritesToFile(t *testing.T) {
	dir := t.TempDir()
	cfg := &ClientConfig{
		LogLevel:     "Info",
		LogPath:      dir,
		DebugLogPath: filepath.Join(dir, "debug.log"),
	}
	lg := NewLogger(cfg)
	if lg == nil {
		t.Fatal("NewLogger returned nil")
	}
	if lg.normalWriter == nil || lg.normalWriter.UseStdout {
		t.Errorf("LogPath set should not use stdout, got %+v", lg.normalWriter)
	}
	normalPath := filepath.Join(dir, logName)
	if _, err := os.Stat(normalPath); err != nil {
		t.Errorf("normal log file not created: %v", err)
	}
	if _, err := os.Stat(cfg.DebugLogPath); err != nil {
		t.Errorf("debug log file not created: %v", err)
	}
	if lg.debugWriter == lg.normalWriter {
		t.Errorf("debug writer should be distinct when DebugLogPath is set")
	}
}

func TestNewLoggerNil(t *testing.T) {
	// nil cfg uses defaults; must not panic, must write to stdout.
	lg := NewLogger(nil)
	if lg == nil {
		t.Fatal("NewLogger(nil) returned nil")
	}
	if lg.normalWriter == nil || !lg.normalWriter.UseStdout {
		t.Errorf("NewLogger(nil) should default to stdout writer")
	}
	if lg.baseLevel != _Debug {
		t.Errorf("default log level = %d, want _Debug (%d)", lg.baseLevel, _Debug)
	}
}

// TestLoggerOutputToFile exercises the logging methods (output, Info, Debug,
// Warn, Error) through a file-backed logger so we can read back what was
// written without relying on the global stdout logger or os.Exit.
func TestLoggerOutputToFile(t *testing.T) {
	dir := t.TempDir()
	lg := NewLogger(&ClientConfig{LogLevel: "Debug", LogPath: dir})
	if lg == nil {
		t.Fatal("NewLogger returned nil")
	}

	// baseLevel = Debug, so all levels pass the filter.
	lg.Info("info line")
	lg.Warn("warn line")
	lg.Error("error line")
	lg.Debug("debug line runs through debugWriter")

	normal := readFile(t, filepath.Join(dir, logName))
	for _, want := range []string{"[Info] info line\n", "[Warn] warn line\n", "[Error] error line\n"} {
		if !strings.Contains(normal, want) {
			t.Errorf("normal log missing %q; got:\n%s", want, normal)
		}
	}
	// Debug output goes to the debug writer. With no DebugLogPath the debug
	// writer aliases the normal writer, so the debug line lands in the same
	// file (prefixed [Debug]).
	if !strings.Contains(normal, "[Debug] debug line runs through debugWriter\n") {
		t.Errorf("debug line missing from log (debugWriter aliases normal writer):\n%s", normal)
	}
}

// TestLoggerLevelFiltering verifies baseLevel gates lower-priority messages.
func TestLoggerLevelFiltering(t *testing.T) {
	dir := t.TempDir()
	// baseLevel = Warn: Debug and Info are suppressed, Warn and above pass.
	lg := NewLogger(&ClientConfig{LogLevel: "Warn", LogPath: dir})
	lg.Debug("dbg")
	lg.Info("inf")
	lg.Warn("wrn")
	lg.Error("err")

	data := readFile(t, filepath.Join(dir, logName))
	if strings.Contains(data, "[Debug]") || strings.Contains(data, "[Info]") {
		t.Errorf("Debug/Info should be filtered at Warn level; got:\n%s", data)
	}
	if !strings.Contains(data, "[Warn] wrn\n") || !strings.Contains(data, "[Error] err\n") {
		t.Errorf("Warn/Error should pass at Warn level; got:\n%s", data)
	}
}

// TestSetAndGetBaseLogger covers the default-logger registry: setting a logger
// makes it reachable via GetBaseLogger and the package-level Info/Error.
func TestSetAndGetBaseLogger(t *testing.T) {
	dir := t.TempDir()
	// Use LogLevel Debug so every package-level wrapper passes the level gate,
	// exercising the forwarding paths for Debug/Info/Warn/Error alike.
	lg := NewLogger(&ClientConfig{LogLevel: "Debug", LogPath: dir})
	SetDefaultLogger(lg)

	got := GetBaseLogger()
	if got == nil {
		t.Fatal("GetBaseLogger returned nil")
	}
	if got != lg.StdLogger() {
		t.Errorf("GetBaseLogger() != lg.StdLogger()")
	}

	// Package-level wrappers go through the default logger and write files.
	Info("via package", "Info")
	Error("via package", "Error")
	Warn("via package", "Warn")
	Debug("via package", "Debug")

	data := readFile(t, filepath.Join(dir, logName))
	for _, want := range []string{
		"[Info] via package Info\n",
		"[Error] via package Error\n",
		"[Warn] via package Warn\n",
		// Without a DebugLogPath the debug writer aliases the normal writer.
		"[Debug] via package Debug\n",
	} {
		if !strings.Contains(data, want) {
			t.Errorf("default logger missing %q; got:\n%s", want, data)
		}
	}
}

// TestNewLoggerFallsBackToStdoutOnMkdirError covers newFile's failure path:
// when the log directory cannot be created, the writer falls back to writing
// os.Stdout instead of panicking or leaving a nil File. (UseStdout stays as
// constructed — only File is redirected.)
func TestNewLoggerFallsBackToStdoutOnMkdirError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("create blocker file: %v", err)
	}
	// LogPath's parent is a regular file, so MkdirAll must fail.
	cfg := &ClientConfig{LogPath: filepath.Join(blocker, "sub")}
	lg := NewLogger(cfg)
	if lg == nil {
		t.Fatal("NewLogger returned nil")
	}
	if lg.normalWriter == nil {
		t.Fatal("normalWriter is nil")
	}
	if lg.normalWriter.UseStdout {
		t.Errorf("UseStdout should stay false (LogPath was set); got true")
	}
	if lg.normalWriter.File != os.Stdout {
		t.Errorf("expected File to fall back to os.Stdout after MkdirAll failure, got %v", lg.normalWriter.File)
	}
}

// TestSetupSmoke covers Setup wiring: it builds a config and initializes the
// global logger. With nil cfg it must apply defaults and set a stdout logger
// (no kernel interaction here — kernel work lives in sibling packages).
func TestSetupSmoke(t *testing.T) {
	Setup(nil)
	if getDefaultLogger() == nil {
		t.Fatal("Setup(nil) did not install a default logger")
	}

	dir := t.TempDir()
	Setup(&ClientConfig{LogLevel: "Info", LogPath: dir})
	lg := getDefaultLogger()
	if lg == nil {
		t.Fatal("Setup(cfg) did not install a default logger")
	}
	if lg.baseLevel != _Info {
		t.Errorf("Setup logger baseLevel = %d, want _Info", lg.baseLevel)
	}
	if _, err := os.Stat(filepath.Join(dir, logName)); err != nil {
		t.Errorf("Setup did not create the log file: %v", err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestNilReceiverRoutesToDefaultLogger covers the nil-receiver guards in the
// Logger methods: calling a method on a nil *Logger must dispatch to whatever
// the current default logger is rather than panicking.
func TestNilReceiverRoutesToDefaultLogger(t *testing.T) {
	dir := t.TempDir()
	lg := NewLogger(&ClientConfig{LogLevel: "Debug", LogPath: dir})
	SetDefaultLogger(lg)

	var nilL *Logger = nil
	nilL.Info("nil receiver info")
	nilL.Warn("nil receiver warn")
	nilL.Error("nil receiver error")
	nilL.Debug("nil receiver debug")

	data := readFile(t, filepath.Join(dir, logName))
	for _, want := range []string{
		"[Info] nil receiver info\n",
		"[Warn] nil receiver warn\n",
		"[Error] nil receiver error\n",
		"[Debug] nil receiver debug\n",
	} {
		if !strings.Contains(data, want) {
			t.Errorf("nil receiver output missing %q; got:\n%s", want, data)
		}
	}
}
