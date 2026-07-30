//go:build !windows && !js

package rwcancel

import (
	"os"
	"syscall"
	"testing"
)

func TestRetryAfterError(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{syscall.EAGAIN, true},
		{syscall.EINTR, true},
		{syscall.EPIPE, false},
		{os.ErrClosed, false},
		{nil, false},
	}
	for _, tt := range tests {
		if got := RetryAfterError(tt.err); got != tt.want {
			t.Fatalf("RetryAfterError(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestNewRWCancelFromPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	rwc, err := NewRWCancel(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()

	if rwc.fd != int(r.Fd()) {
		t.Fatalf("fd = %d, want %d", rwc.fd, r.Fd())
	}
}

func TestRWCancelReadWrite(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	rwc, err := NewRWCancel(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()

	msg := []byte("hello")
	n, err := w.Write(msg)
	if err != nil || n != len(msg) {
		t.Fatalf("write on pipe: n=%d err=%v", n, err)
	}

	buf := make([]byte, 16)
	n, err = rwc.Read(buf)
	if err != nil {
		t.Fatalf("rwc.Read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("read %q, want %q", string(buf[:n]), "hello")
	}
}

func TestRWCancelCancelUnblocksRead(t *testing.T) {
	r, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	rwc, err := NewRWCancel(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()

	// Cancel will write a byte to the closing pipe, making
	// poll on the closing reader fd's Revents != 0, so
	// ReadyRead returns false.
	err = rwc.Cancel()
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	// After Cancel, ReadyRead should return false (the close fd has data).
	if rwc.ReadyRead() {
		t.Fatal("ReadyRead should return false after Cancel")
	}

	// Reading after cancel should return os.ErrClosed
	buf := make([]byte, 16)
	_, err = rwc.Read(buf)
	if err != os.ErrClosed {
		t.Fatalf("Read after cancel: want os.ErrClosed, got %v", err)
	}
}

func TestRWCancelWriteWorks(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	// RWCancel on the write end of the pipe
	rwc, err := NewRWCancel(int(w.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()

	// Write to the pipe should work
	msg := []byte("test data")
	n, err := rwc.Write(msg)
	if err != nil {
		t.Fatalf("rwc.Write: %v", err)
	}
	if n != len(msg) {
		t.Fatalf("rwc.Write n=%d, want %d", n, len(msg))
	}

	// Verify data arrived on the read end
	buf := make([]byte, 32)
	n, err = r.Read(buf)
	if err != nil {
		t.Fatalf("r.Read: %v", err)
	}
	if string(buf[:n]) != "test data" {
		t.Fatalf("read %q, want %q", string(buf[:n]), "test data")
	}
}

func TestRWCancelCloseIsSafe(t *testing.T) {
	r, _, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	rwc, err := NewRWCancel(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	rwc.Close()
	// Double close should not panic
	rwc.Close()
}

func TestRWCancelReadAfterClosePipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	rwc, err := NewRWCancel(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()

	// Close the write end — this makes the read return EOF
	w.Close()

	buf := make([]byte, 16)
	n, err := rwc.Read(buf)
	if err != nil {
		t.Fatalf("rwc.Read after write-end closed: expecting EOF, got %v", err)
	}
	if n != 0 {
		t.Fatalf("rwc.Read n=%d, want 0 (EOF)", n)
	}
}
