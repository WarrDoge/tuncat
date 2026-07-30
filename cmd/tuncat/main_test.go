package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMainObscureSubcommand verifies that the "obscure" subcommand is
// dispatched to cli.RunObscure. We build the binary and run it with
// "obscure" piped input, checking for the expected prompt output.
func TestMainObscureSubcommand(t *testing.T) {
	bin := buildTestBinary(t)

	cmd := exec.Command(bin, "obscure")
	cmd.Stdin = strings.NewReader("test-password\n")
	out, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("obscure subcommand failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(string(out), "obscured:") {
		t.Fatalf("expected obscure output to contain 'obscured:', got: %s", out)
	}
}

// TestMainExitsNonZeroOnMissingConfig verifies that running without a config
// file (and no flags) returns exit code 1.
func TestMainExitsNonZeroOnMissingConfig(t *testing.T) {
	bin := buildTestBinary(t)

	cmd := exec.Command(bin)
	// Ensure no config file is found by using an empty temp dir.
	tmp := t.TempDir()
	cmd.Dir = tmp
	err := cmd.Run()

	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 1 {
			t.Fatalf("expected exit code 1, got %d", exitErr.ExitCode())
		}
	} else if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestMainVersionFlag verifies that --version prints the version string
// and exits with code 0.
func TestMainVersionFlag(t *testing.T) {
	bin := buildTestBinary(t)

	cmd := exec.Command(bin, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--version failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(string(out), "tuncat") {
		t.Fatalf("expected version output to contain 'tuncat', got: %s", out)
	}
}

// TestMainNonExistentFlag verifies that an unrecognised flag causes a
// non-zero exit.
func TestMainNonExistentFlag(t *testing.T) {
	bin := buildTestBinary(t)

	cmd := exec.Command(bin, "--nonexistent-flag")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit for unknown flag")
	}
}

// buildTestBinary compiles the current package and returns the path to the
// temporary binary. Each test gets its own binary to avoid interference.
func buildTestBinary(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	bin := filepath.Join(dir, "tuncat.test")

	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = filepath.Dir(".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\noutput: %s", err, out)
	}

	// Default OS_ARGV behaviour expects flags; reset to avoid inheriting
	// the test runner's flags.
	cleanup := func() {
		os.Args = os.Args[:1]
	}
	t.Cleanup(cleanup)

	return bin
}
