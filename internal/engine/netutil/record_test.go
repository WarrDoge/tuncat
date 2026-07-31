package netutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewRecord(t *testing.T) {
	r := NewRecord("/tmp/test-record")
	if r.Filename != "/tmp/test-record" {
		t.Fatalf("NewRecord Filename = %q, want %q", r.Filename, "/tmp/test-record")
	}
	if r.Contents == nil {
		t.Fatal("NewRecord Contents should be non-nil")
	}
	if len(r.Contents) != 0 {
		t.Fatalf("NewRecord Contents should be empty, got %d items", len(r.Contents))
	}
}

func TestReadLinesFileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exists.txt")
	if err := os.WriteFile(path, []byte("line1\nline2\nline3\n"), 0644); err != nil {
		t.Fatal(err)
	}

	r := NewRecord(path)
	if err := r.readLines(); err != nil {
		t.Fatalf("readLines on existing file: %v", err)
	}
	want := []string{"line1", "line2", "line3"}
	if len(r.Contents) != len(want) {
		t.Fatalf("readLines got %d lines, want %d", len(r.Contents), len(want))
	}
	for i, line := range want {
		if r.Contents[i] != line {
			t.Fatalf("readLines line[%d] = %q, want %q", i, r.Contents[i], line)
		}
	}
}

func TestReadLinesFileNotExists(t *testing.T) {
	r := NewRecord("/tmp/nonexistent-file-for-test-12345")
	if err := r.readLines(); err != nil {
		t.Fatalf("readLines on missing file should return nil error, got: %v", err)
	}
	if len(r.Contents) != 0 {
		t.Fatalf("readLines on missing file should leave Contents empty, got %d items", len(r.Contents))
	}
}

func TestReadLinesEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	r := NewRecord(path)
	if err := r.readLines(); err != nil {
		t.Fatalf("readLines on empty file: %v", err)
	}
	if len(r.Contents) != 0 {
		t.Fatalf("readLines on empty file should leave Contents empty, got %d items", len(r.Contents))
	}
}

func TestReadLinesSkipsEmptyLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blanks.txt")
	if err := os.WriteFile(path, []byte("a\n\nb\n\n\nc\n"), 0644); err != nil {
		t.Fatal(err)
	}

	r := NewRecord(path)
	if err := r.readLines(); err != nil {
		t.Fatalf("readLines with blank lines: %v", err)
	}
	want := []string{"a", "b", "c"}
	if len(r.Contents) != len(want) {
		t.Fatalf("readLines got %d lines, want %d", len(r.Contents), len(want))
	}
	for i, line := range want {
		if r.Contents[i] != line {
			t.Fatalf("readLines line[%d] = %q, want %q", i, r.Contents[i], line)
		}
	}
}
