package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDir creates a temporary directory outside /tmp (which may be full).
func testDir(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	dir := filepath.Join("/home/tuna/.cache/tuncat-test", hex.EncodeToString(b))
	err := os.MkdirAll(dir, 0o755)
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// ---------------------------------------------------------------------------
// config.go — defaults & constructors
// ---------------------------------------------------------------------------

func TestNewClientConfig_Defaults(t *testing.T) {
	cfg := NewClientConfig()
	require.NotNil(t, cfg)

	assert.Equal(t, "Debug", cfg.LogLevel)
	assert.Equal(t, "", cfg.LogPath)
	assert.Equal(t, "", cfg.DebugLogPath)
	assert.Equal(t, "127.0.0.1:6210", cfg.RPCAddr)
	assert.Equal(t, false, cfg.InsecureSkipVerify)
	assert.Equal(t, true, cfg.CiscoCompat)
	assert.Equal(t, false, cfg.NoDTLS)
	assert.Equal(t, "AnyConnect", cfg.AgentName)
	assert.Equal(t, "4.10.07062", cfg.AgentVersion)
	assert.Equal(t, 1200, cfg.BaseMTU)
	assert.Empty(t, cfg.SplitRoutes)
	assert.Empty(t, cfg.DNSDomains)
	assert.Equal(t, "", cfg.ServerCertPin)
}

func TestApplyDefaults_Nil(t *testing.T) {
	ApplyDefaults(nil) // must not panic
}

func TestApplyDefaults_PreservesExistingValues(t *testing.T) {
	cfg := &ClientConfig{
		LogLevel:           "Warn",
		RPCAddr:            "10.0.0.1:9999",
		InsecureSkipVerify: true,
		CiscoCompat:        false,
		NoDTLS:             true,
		AgentName:          "CustomAgent",
		AgentVersion:       "9.9.9",
		BaseMTU:            9000,
		SplitRoutes:        []string{"10.0.0.0/8"},
		DNSDomains:         []string{"example.com"},
		ServerCertPin:      "sha256:abc123",
	}
	ApplyDefaults(cfg)

	// Values that are only set when empty should be preserved.
	assert.Equal(t, "Warn", cfg.LogLevel)
	assert.Equal(t, "10.0.0.1:9999", cfg.RPCAddr)
	assert.Equal(t, true, cfg.NoDTLS)
	assert.Equal(t, "CustomAgent", cfg.AgentName)
	assert.Equal(t, "9.9.9", cfg.AgentVersion)
	assert.Equal(t, 9000, cfg.BaseMTU)
	assert.Equal(t, []string{"10.0.0.0/8"}, cfg.SplitRoutes)
	assert.Equal(t, []string{"example.com"}, cfg.DNSDomains)
	assert.Equal(t, "sha256:abc123", cfg.ServerCertPin)

	// InsecureSkipVerify and CiscoCompat are unconditionally overridden.
	assert.False(t, cfg.InsecureSkipVerify, "InsecureSkipVerify is always forced to false")
	assert.True(t, cfg.CiscoCompat, "CiscoCompat is always forced to true")
}

func TestApplyDefaults_ForcedValues(t *testing.T) {
	cfg := &ClientConfig{InsecureSkipVerify: true, CiscoCompat: false}
	ApplyDefaults(cfg)
	assert.False(t, cfg.InsecureSkipVerify)
	assert.True(t, cfg.CiscoCompat)
}

func TestNewInterface(t *testing.T) {
	iface := NewInterface()
	assert.Equal(t, "", iface.Name)
	assert.Equal(t, "", iface.Ip4)
	assert.Equal(t, "", iface.Mac)
	assert.Equal(t, "", iface.Gateway)
}

// ---------------------------------------------------------------------------
// log.go — logLevel2Int
// ---------------------------------------------------------------------------

func TestLogLevel2Int(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"Debug", _Debug},
		{"Info", _Info},
		{"Warn", _Warn},
		{"Error", _Error},
		{"Fatal", _Fatal},
		{"debug", _Debug}, {"DEBUG", _Debug}, {"DeBuG", _Debug},
		{"info", _Info}, {"INFO", _Info},
		{"warn", _Warn}, {"WARN", _Warn},
		{"error", _Error}, {"ERROR", _Error},
		{"fatal", _Fatal}, {"FATAL", _Fatal},
		{"", _Info},
		{"unknown", _Info},
		{"Trace", _Info},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, logLevel2Int(tc.input), "logLevel2Int(%q)", tc.input)
		})
	}
}

// ---------------------------------------------------------------------------
// log.go — Logger creation and level filtering
// ---------------------------------------------------------------------------

func TestNewLogger_StdoutWhenEmptyPaths(t *testing.T) {
	cfg := &ClientConfig{LogLevel: "Debug"}
	logger := NewLogger(cfg)
	require.NotNil(t, logger)

	assert.Equal(t, _Debug, logger.baseLevel)
	assert.True(t, logger.normalWriter.UseStdout)
	assert.Equal(t, os.Stdout, logger.normalWriter.File)
	assert.Same(t, logger.normalWriter, logger.debugWriter)
}

func TestNewLogger_NilConfigGetsDefaults(t *testing.T) {
	logger := NewLogger(nil)
	require.NotNil(t, logger)
	assert.Equal(t, _Debug, logger.baseLevel)
	assert.True(t, logger.normalWriter.UseStdout)
}

func TestNewLogger_WithDebugLogPath(t *testing.T) {
	dir := testDir(t)
	debugPath := filepath.Join(dir, "debug.log")

	cfg := &ClientConfig{
		LogLevel:     "Debug",
		LogPath:      dir,
		DebugLogPath: debugPath,
	}
	logger := NewLogger(cfg)
	require.NotNil(t, logger)

	assert.False(t, logger.normalWriter.UseStdout, "LogPath set -> file logging")
	assert.False(t, logger.debugWriter.UseStdout)
	assert.NotSame(t, logger.normalWriter, logger.debugWriter, "separate writers")

	assert.FileExists(t, filepath.Join(dir, logName), "normal log file (vpnagent.log)")
	assert.FileExists(t, debugPath, "debug log file")

	closeWriters(logger)
}

func TestLogger_LevelFiltering(t *testing.T) {
	dir := testDir(t)
	normalPath := filepath.Join(dir, logName)
	debugPath := filepath.Join(dir, "debug.log")

	cfg := &ClientConfig{
		LogLevel:     "Info",
		LogPath:      dir,
		DebugLogPath: debugPath,
	}
	logger := NewLogger(cfg)
	require.NotNil(t, logger)
	defer closeWriters(logger)

	logger.Debug("should", "not", "appear")
	logger.Info("info", "message")

	// Debug output is suppressed at Info level
	debugContent := readFile(t, debugPath)
	assert.Empty(t, debugContent, "Debug output suppressed at Info level")

	// Info message passes through
	normalContent := readFile(t, normalPath)
	assert.Contains(t, normalContent, "[Info] info message")
}

func TestLogger_AllLevelsPassAtDebugLevel(t *testing.T) {
	dir := testDir(t)
	normalPath := filepath.Join(dir, logName)
	debugPath := filepath.Join(dir, "debug.log")

	cfg := &ClientConfig{
		LogLevel:     "Debug",
		LogPath:      dir,
		DebugLogPath: debugPath,
	}
	logger := NewLogger(cfg)
	require.NotNil(t, logger)
	defer closeWriters(logger)

	logger.Debug("dbg")
	logger.Info("inf")
	logger.Warn("wrn")
	logger.Error("err")

	normalContent := readFile(t, normalPath)
	debugContent := readFile(t, debugPath)

	assert.Contains(t, normalContent, "[Info] inf")
	assert.Contains(t, normalContent, "[Warn] wrn")
	assert.Contains(t, normalContent, "[Error] err")
	assert.Contains(t, debugContent, "[Debug] dbg")
}

func TestLogger_OutputFatalLevel(t *testing.T) {
	dir := testDir(t)
	normalPath := filepath.Join(dir, logName)

	cfg := &ClientConfig{
		LogLevel: "Debug",
		LogPath:  dir,
	}
	logger := NewLogger(cfg)
	require.NotNil(t, logger)
	defer closeWriters(logger)

	logger.output(_Fatal, "fatal", "message")
	normalContent := readFile(t, normalPath)
	assert.Contains(t, normalContent, "[Fatal] fatal message")
}

// ---------------------------------------------------------------------------
// log.go — default logger singleton
// ---------------------------------------------------------------------------

func TestGetDefaultLogger_InitializesOnFirstCall(t *testing.T) {
	resetDefaultLogger(t)

	l1 := getDefaultLogger()
	require.NotNil(t, l1)

	l2 := getDefaultLogger() // idempotent
	assert.Same(t, l1, l2)
}

func TestSetDefaultLogger(t *testing.T) {
	resetDefaultLogger(t)

	myLogger := &Logger{baseLevel: _Error}
	SetDefaultLogger(myLogger)
	assert.Same(t, myLogger, getDefaultLogger())
}

func TestPackageLevelFunctions(t *testing.T) {
	dir := testDir(t)
	normalPath := filepath.Join(dir, logName)
	debugPath := filepath.Join(dir, "debug.log")

	cfg := &ClientConfig{
		LogLevel:     "Debug",
		LogPath:      dir,
		DebugLogPath: debugPath,
	}
	logger := NewLogger(cfg)
	defer closeWriters(logger)

	resetDefaultLogger(t)
	SetDefaultLogger(logger)

	Debug("debug", "msg")
	Info("info", "msg")
	Warn("warn", "msg")
	Error("error", "msg")

	normalContent := readFile(t, normalPath)
	debugContent := readFile(t, debugPath)

	assert.Contains(t, normalContent, "[Info] info msg")
	assert.Contains(t, normalContent, "[Warn] warn msg")
	assert.Contains(t, normalContent, "[Error] error msg")
	assert.Contains(t, debugContent, "[Debug] debug msg")
}

func TestGetBaseLogger(t *testing.T) {
	logger := GetBaseLogger()
	require.NotNil(t, logger)
}

func TestLogger_NilReceiver(t *testing.T) {
	dir := testDir(t)
	normalPath := filepath.Join(dir, logName)
	debugPath := filepath.Join(dir, "debug.log")

	cfg := &ClientConfig{
		LogLevel:     "Debug",
		LogPath:      dir,
		DebugLogPath: debugPath,
	}
	logger := NewLogger(cfg)
	defer closeWriters(logger)

	resetDefaultLogger(t)
	SetDefaultLogger(logger)

	var l *Logger
	assert.NotPanics(t, func() { l.StdLogger() })
	assert.NotPanics(t, func() { l.output(_Info, "hello") })
	assert.NotPanics(t, func() { l.Debug("hello") })
	assert.NotPanics(t, func() { l.Info("hello") })
	assert.NotPanics(t, func() { l.Warn("hello") })
	assert.NotPanics(t, func() { l.Error("hello") })

	// All nil-receiver calls should have delegated to the default logger
	content := readFile(t, normalPath)
	assert.Contains(t, content, "[Info] hello")
	assert.Contains(t, content, "[Warn] hello")
	assert.Contains(t, content, "[Error] hello")

	debugContent := readFile(t, debugPath)
	assert.Contains(t, debugContent, "[Debug] hello")
}

// ---------------------------------------------------------------------------
// log.go — logWriter.newFile
// ---------------------------------------------------------------------------

func TestLogWriterNewFile_StdoutWhenUseStdout(t *testing.T) {
	lw := &logWriter{UseStdout: true}
	lw.newFile()
	assert.Equal(t, os.Stdout, lw.File)
}

func TestLogWriterNewFile_StdoutWhenEmptyName(t *testing.T) {
	lw := &logWriter{UseStdout: false, FileName: ""}
	lw.newFile()
	assert.Equal(t, os.Stdout, lw.File)
}

func TestLogWriterNewFile_CreatesFile(t *testing.T) {
	dir := testDir(t)
	path := filepath.Join(dir, "test.log")
	lw := &logWriter{UseStdout: false, FileName: path}
	lw.newFile()

	require.NotNil(t, lw.File)
	assert.NotEqual(t, os.Stdout, lw.File)
	assert.FileExists(t, path)
	lw.File.Close()
}

// ---------------------------------------------------------------------------
// setup.go
// ---------------------------------------------------------------------------

func TestSetup_NilConfig(t *testing.T) {
	resetDefaultLogger(t)

	Setup(nil)
	require.NotNil(t, getDefaultLogger())
}

func TestSetup_WithConfig(t *testing.T) {
	resetDefaultLogger(t)

	cfg := &ClientConfig{LogLevel: "Error"}
	Setup(cfg)
	logger := getDefaultLogger()
	require.NotNil(t, logger)
	assert.Equal(t, _Error, logger.baseLevel)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// resetDefaultLogger resets the package-level default logger to nil so tests
// can observe initialization or inject their own logger.
func resetDefaultLogger(t *testing.T) {
	t.Helper()
	origLogger := defaultLogger
	origMu := defaultLoggerMu
	t.Cleanup(func() {
		defaultLogger = origLogger
		defaultLoggerMu = origMu
	})
	defaultLoggerMu = sync.RWMutex{}
	defaultLogger = nil
}

// closeWriters closes the file handles held by a Logger's writers.
func closeWriters(l *Logger) {
	if l.normalWriter != nil && l.normalWriter.File != nil && l.normalWriter.File != os.Stdout {
		l.normalWriter.File.Close()
	}
	if l.debugWriter != nil && l.debugWriter.File != nil && l.debugWriter.File != os.Stdout && l.debugWriter != l.normalWriter {
		l.debugWriter.File.Close()
	}
}

// readFile reads a file and returns its content as a string.
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}
