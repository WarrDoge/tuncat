//go:build linux

package device

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeTUN returns a NativeTun backed by a socket pair instead of a real TUN
// device. Socket pairs are bidirectional, so Read/Write/Flush all work with
// the single fd, just like a real TUN fd.
// Returns: tun, peerFd (the "other side" of the TUN for injecting/reading data).
func fakeTUN(t *testing.T) (*NativeTun, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	tunFd := fds[0]
	peerFd := fds[1]

	file := os.NewFile(uintptr(tunFd), "tun-test")
	peerFile := os.NewFile(uintptr(peerFd), "tun-test-peer")

	t.Cleanup(func() {
		file.Close()
		peerFile.Close()
	})

	tun := &NativeTun{
		tunFile: file,
		events:  make(chan Event, 5),
		errors:  make(chan error, 5),
		nopi:    true,
	}
	return tun, peerFile
}

func fakeTUNNoPI(t *testing.T) (*NativeTun, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	tunFd := fds[0]
	peerFd := fds[1]

	file := os.NewFile(uintptr(tunFd), "tun-test")
	peerFile := os.NewFile(uintptr(peerFd), "tun-test-peer")

	t.Cleanup(func() {
		file.Close()
		peerFile.Close()
	})

	tun := &NativeTun{
		tunFile: file,
		events:  make(chan Event, 5),
		errors:  make(chan error, 5),
		nopi:    false,
	}
	return tun, peerFile
}

func TestNativeTun_WriteAndFlush(t *testing.T) {
	tun, peer := fakeTUN(t)

	n, err := tun.Write([]byte("hello world"), 0)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 11 {
		t.Fatalf("Write returned %d, want 11", n)
	}

	// Data should not arrive on the peer before Flush.
	buf := make([]byte, 64)
	r2 := make(chan int, 1)
	go func() {
		n, _ := peer.Read(buf)
		r2 <- n
	}()
	select {
	case <-r2:
		t.Fatal("data arrived before Flush()")
	default:
	}

	if err := tun.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	nr := <-r2
	if nr != 11 {
		t.Fatalf("read %d bytes after Flush, want 11", nr)
	}
	if string(buf[:11]) != "hello world" {
		t.Fatalf("got %q, want %q", string(buf[:11]), "hello world")
	}
}

func TestNativeTun_WriteMultipleAndFlush(t *testing.T) {
	tun, peer := fakeTUN(t)

	for i := 0; i < 5; i++ {
		_, err := tun.Write([]byte("packet data"), 0)
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	if err := tun.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Stream sockets may coalesce writes, so read until we get everything.
	total := 0
	want := 5 * len("packet data")
	buf := make([]byte, 256)
	for total < want {
		n, err := peer.Read(buf[total:])
		if err != nil {
			t.Fatalf("read after %d/%d bytes: %v", total, want, err)
		}
		total += n
	}
	if total != want {
		t.Fatalf("read %d total bytes, want %d", total, want)
	}
}

func TestNativeTun_FlushEmpty(t *testing.T) {
	tun, _ := fakeTUN(t)

	if err := tun.Flush(); err != nil {
		t.Fatalf("Flush on empty buffer: %v", err)
	}
}

func TestNativeTun_Read(t *testing.T) {
	tun, peer := fakeTUN(t)

	peer.Write([]byte("hello from tun"))
	peer.Close()

	buf := make([]byte, 128)
	n, err := tun.Read(buf, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 14 {
		t.Fatalf("Read returned %d, want 14", n)
	}
	if string(buf[:n]) != "hello from tun" {
		t.Fatalf("got %q, want %q", string(buf[:n]), "hello from tun")
	}
}

func TestNativeTun_ReadWithPISkipped(t *testing.T) {
	tun, peer := fakeTUNNoPI(t)

	// Write 4 bytes of PI + 11 bytes of payload.
	piPacket := make([]byte, 15)
	piPacket[0] = 0x00
	piPacket[1] = 0x00
	piPacket[2] = 0x08
	piPacket[3] = 0x00 // IPv4 EtherType
	copy(piPacket[4:], []byte("hello world"))
	peer.Write(piPacket)
	peer.Close()

	// offset=4 is needed for Read when nopi=false.
	buf := make([]byte, 128)
	n, err := tun.Read(buf, 4)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 11 {
		t.Fatalf("Read returned %d, want 11", n)
	}
	if string(buf[4:4+n]) != "hello world" {
		t.Fatalf("got %q, want %q", string(buf[4:4+n]), "hello world")
	}
}

func TestNativeTun_ReadError(t *testing.T) {
	tun, _ := fakeTUN(t)

	tun.errors <- syscall.EIO

	buf := make([]byte, 128)
	_, err := tun.Read(buf, 0)
	if err == nil {
		t.Fatal("expected error from Read, got nil")
	}
}

func TestNativeTun_File(t *testing.T) {
	tun, _ := fakeTUN(t)

	f := tun.File()
	if f == nil {
		t.Fatal("File() returned nil")
	}
}

func TestNativeTun_Events(t *testing.T) {
	tun, _ := fakeTUN(t)

	ch := tun.Events()
	if ch == nil {
		t.Fatal("Events() returned nil channel")
	}

	select {
	case tun.events <- EventUp:
	default:
		t.Fatal("events channel full")
	}
	select {
	case ev := <-ch:
		if ev != EventUp {
			t.Fatalf("got event %d, want %d", ev, EventUp)
		}
	default:
		t.Fatal("expected EventUp on events channel")
	}
}

func TestNativeTun_Close(t *testing.T) {
	tun, _ := fakeTUN(t)

	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := tun.Close(); err != nil {
		t.Fatalf("Close (second): %v", err)
	}
}

func TestNativeTun_WriteEBADFD(t *testing.T) {
	tun, peer := fakeTUN(t)
	peer.Close()
	tun.tunFile.Close()

	_, err := tun.Write([]byte("data"), 0)
	if err != nil {
		t.Fatalf("buffered Write after close: %v", err)
	}

	err = tun.Flush()
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Flush after close: got %v, want os.ErrClosed", err)
	}
}
