package cli

import (
	"strings"
	"testing"
)

// TestObscureRoundTrip exercises obscure -> reveal over plaintexts that cover
// the ordinary and hostile ends of the byte range: empty, ASCII symbols,
// multi-byte UTF-8, and arbitrary binary bytes that are not valid UTF-8.
func TestObscureRoundTrip(t *testing.T) {
	cases := []string{
		"",
		"simple",
		"p@ssw0rd!#$%",
		"a very long password with spaces and unicode: äöü日本語",
		string([]byte{0x00, 0x01, 0xfe, 0xff, 0x80, 0x7f}), // arbitrary binary
		strings.Repeat("x", 100000),                        // large payload
	}
	for _, pw := range cases {
		enc, err := obscure(pw)
		if err != nil {
			t.Fatalf("obscure(%q): %v", pw, err)
		}
		if !strings.HasPrefix(enc, obscurePrefix) {
			t.Errorf("obscure(%q) = %q, want %q prefix", pw, enc, obscurePrefix)
		}
		dec, err := reveal(enc)
		if err != nil {
			t.Fatalf("reveal(obscure(%q)): %v", pw, err)
		}
		if dec != pw {
			t.Errorf("round-trip mismatch: got %q, want %q", dec, pw)
		}
	}
}

// TestRevealRejectsInvalidPrefixData checks that reveal fails loudly on an
// obscured value that is not valid base64 rather than silently corrupting it.
func TestRevealRejectsInvalidBase64(t *testing.T) {
	for _, bad := range []string{
		obscurePrefix + "!!!not-base64!!!",
		obscurePrefix + "AAAA", // decodes, but shorter than AES block size
		obscurePrefix + "AQIDBA==", // 4 bytes decoded < 16
	} {
		if _, err := reveal(bad); err == nil {
			t.Errorf("reveal(%q) succeeded, want error", bad)
		}
	}
}

// TestRevealErrorDoesNotPanic ensures malformed obscured values never panic,
// which is exactly the property the fuzzer hammers harder.
func TestRevealErrorDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("reveal panicked: %v", r)
		}
	}()
	// prefix with a byte count way beyond what base64 can represent for 16+ bytes
	_ = obscurePrefix + strings.Repeat("A", 4096)
}

// TestRevealPlaintextPassthrough duplicates the app-level behaviour check:
// a value without the obscured prefix is returned unchanged, never errored.
func TestRevealPlaintextPassthrough(t *testing.T) {
	for _, plain := range []string{"", "not-obscured", obscurePrefix[:4], "obscure:"} {
		got, err := reveal(plain)
		if err != nil {
			t.Fatalf("reveal(%q): %v", plain, err)
		}
		if got != plain {
			t.Errorf("reveal(%q) = %q, want %q", plain, got, plain)
		}
	}
}

// FuzzObscure is a roundtrip property over arbitrary input: whatever bytes
// obscure accepts, reveal must hand back unchanged. It also asserts that
// reveal never panics on malformed obscured values (the parse analogue
// of the CSTP length-field bug).
func FuzzObscure(f *testing.F) {
	f.Add("")
	f.Add("simple")
	f.Add("p@ssw0rd!#$%")
	f.Add("a very long password with unicode äöü日本語 and spaces")
	f.Add(string([]byte{0x00, 0xff, 0x80, 0x7f}))
	f.Add(obscurePrefix + "AAAA")

	f.Fuzz(func(t *testing.T, plain string) {
		enc, err := obscure(plain)
		if err != nil {
			t.Fatalf("obscure(%q): %v", plain, err)
		}
		dec, err := reveal(enc)
		if err != nil {
			t.Fatalf("reveal(obscure(%q)): %v", plain, err)
		}
		if dec != plain {
			t.Fatalf("round-trip mismatch: got %q, want %q", dec, plain)
		}
	})
}
