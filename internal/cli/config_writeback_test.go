package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestObscureConfigSecretsInFileEmptyPath locks the early-return guard: no
// config path means no work, no error, nothing to change.
func TestObscureConfigSecretsInFileEmptyPath(t *testing.T) {
	changed, err := obscureConfigSecretsInFile("", map[string]bool{})
	if err != nil {
		t.Fatalf("obscureConfigSecretsInFile(\"\") error: %v", err)
	}
	if changed {
		t.Fatal("obscureConfigSecretsInFile(\"\") should not report a change")
	}
}

// TestObscureConfigSecretsInFileAlreadyObscured proves idempotency: when the
// file is already obscured, write-back is a no-op and leaves the file
// byte-identical. A behaviour-preserving pass must be byte-identical, not just
// "looks the same" — see craft/testing/behaviour-preserving-means-byte-identical.
func TestObscureConfigSecretsInFileAlreadyObscured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	input := strings.Join([]string{
		`server: "vpn.example.com/group"`,
		`password: "obscured:c2VjcmV0Cg=="`,
		`username: "user"`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	changed, err := obscureConfigSecretsInFile(path, map[string]bool{})
	if err != nil {
		t.Fatalf("obscureConfigSecretsInFile error: %v", err)
	}
	if changed {
		t.Fatal("expected no change when secrets are already obscured")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("already-obscured file was rewritten:\n--- before ---\n%s--- after ---\n%s", before, after)
	}
}

// TestObscureConfigSecretsInFileUnwritable covers the write-failure path: an
// unreadable-to-writer but readable file must surface an error AND leave the
// plaintext secret untouched on disk (no partial/corrupt write).
func TestObscureConfigSecretsInFileUnwritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	input := strings.Join([]string{
		`server: "vpn.example.com/group"`,
		`password: "plain-password"`,
		`username: "user"`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}

	// Read permission must remain so the read path succeeds; removing the
	// write bit forces os.WriteFile to fail (we run as uid 1000, not root).
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0600) })

	changed, err := obscureConfigSecretsInFile(path, map[string]bool{})
	if err == nil {
		t.Fatalf("expected write error for read-only config, got err=nil changed=%v", changed)
	}
	if !strings.Contains(err.Error(), "write config write-back") {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Fatal("obscureConfigSecretsInFile should report changed=false on write failure")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "plain-password") {
		t.Fatalf("plaintext secret was lost or partially written on write failure:\n%s", raw)
	}
}

// TestObscureConfigSecretsInFilePartialYAML covers the parse-failure path: a
// file left partially written (truncated YAML) must not be silently overwritten
// with an obscured version of only the fragment that parsed. The error must
// surface and the original bytes must be preserved.
func TestObscureConfigSecretsInFilePartialYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// A partial write: unterminated scalar leaves the YAML stream invalid.
	input := `server: "vpn.example.com/group`
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	changed, err := obscureConfigSecretsInFile(path, map[string]bool{})
	if err == nil {
		t.Fatalf("expected parse error for partially written YAML, got err=nil changed=%v", changed)
	}
	if !strings.Contains(err.Error(), "parse config for write-back") {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Fatal("obscureConfigSecretsInFile should report changed=false on parse failure")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("partially written config was mutated on parse failure:\n--- before ---\n%s--- after ---\n%s", before, after)
	}
}
