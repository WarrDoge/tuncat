/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

//go:build darwin

package device

import (
	"bytes"
	"os"
	"testing"
)

// pipeFile creates a connected pipe pair and returns the write end.
// The read end is drained into a bytes.Buffer in a goroutine.
func pipeFile(buf *bytes.Buffer) *os.File {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	go func() {
		p := make([]byte, 4096)
		for {
			n, err := r.Read(p)
			if err != nil {
				return
			}
			buf.Write(p[:n])
		}
	}()
	return w
}

func TestNativeTunWriteBuffersThenFlush(t *testing.T) {
	var buf bytes.Buffer
	tun := &NativeTun{
		tunFile:  pipeFile(&buf),
		writeBuf: nil,
	}

	packets := [][]byte{
		{0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x1c},
		{0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x2a},
		{0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x3e},
	}

	for _, pkt := range packets {
		n, err := tun.Write(pkt, 4)
		if err != nil {
			t.Fatalf("Write returned unexpected error: %v", err)
		}
		if n != len(pkt) {
			t.Fatalf("Write returned n=%d, want %d", n, len(pkt))
		}
	}

	if len(tun.writeBuf) != len(packets) {
		t.Fatalf("writeBuf length = %d; want %d", len(tun.writeBuf), len(packets))
	}

	err := tun.Flush()
	if err != nil {
		t.Fatalf("Flush returned unexpected error: %v", err)
	}

	if tun.writeBuf != nil {
		t.Fatal("writeBuf was not reset to nil after Flush")
	}

	got := buf.Bytes()
	var expectedLen int
	for _, pkt := range packets {
		expectedLen += len(pkt)
	}
	if len(got) != expectedLen {
		t.Fatalf("tunFile received %d bytes; want %d", len(got), expectedLen)
	}
}

func TestNativeTunFlushEmptyBuffer(t *testing.T) {
	var buf bytes.Buffer
	tun := &NativeTun{
		tunFile:  pipeFile(&buf),
		writeBuf: nil,
	}

	err := tun.Flush()
	if err != nil {
		t.Fatalf("Flush on empty buffer returned error: %v", err)
	}
}

func TestNativeTunFlushWriteError(t *testing.T) {
	// Write to /dev/full to trigger ENOSPC
	f, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skip("/dev/full not available")
	}
	defer f.Close()

	tun := &NativeTun{
		tunFile:  f,
		writeBuf: [][]byte{{0x01, 0x02, 0x03}},
	}

	err = tun.Flush()
	if err == nil {
		t.Fatal("expected write error from Flush, got nil")
	}
}

func TestNativeTunFlushEBADFD(t *testing.T) {
	tun := &NativeTun{
		tunFile:  nil,
		writeBuf: [][]byte{{0x01, 0x02, 0x03}},
	}

	err := tun.Flush()
	if err == nil {
		t.Fatal("expected an error from Flush on nil fd, got nil")
	}
}
