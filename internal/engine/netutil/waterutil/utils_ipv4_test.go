package waterutil

import (
	"net"
	"testing"
)

func TestIPv4DSCP(t *testing.T) {
	tests := []struct {
		name  string
		packet []byte
		want  byte
	}{
		{"zero", []byte{0x00, 0x00}, 0},
		{"dscp cs0", []byte{0x00, 0x04}, 1},  // 0x04 >> 2 = 1
		{"dscp ef", []byte{0x00, 0xB8}, 46},   // 0xB8 >> 2 = 46
		{"dscp max", []byte{0x00, 0xFC}, 63},  // 0xFC >> 2 = 63
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IPv4DSCP(tt.packet); got != tt.want {
				t.Fatalf("IPv4DSCP = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestIPv4ECN(t *testing.T) {
	tests := []struct {
		name  string
		packet []byte
		want  byte
	}{
		{"not-ect", []byte{0x00, 0x00}, 0},
		{"ect1", []byte{0x00, 0x01}, 1},
		{"ect0", []byte{0x00, 0x02}, 2},
		{"ce", []byte{0x00, 0x03}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IPv4ECN(tt.packet); got != tt.want {
				t.Fatalf("IPv4ECN = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestIPv4Identification(t *testing.T) {
	pkt := []byte{0, 0, 0, 0, 0xAB, 0xCD, 0, 0}
	got := IPv4Identification(pkt)
	if got != [2]byte{0xAB, 0xCD} {
		t.Fatalf("IPv4Identification = %x, want [ab cd]", got)
	}
}

func TestIPv4TTL(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[8] = 64
	if got := IPv4TTL(pkt); got != 64 {
		t.Fatalf("IPv4TTL = %d, want 64", got)
	}
}

func TestIPv4Protocol(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[9] = byte(TCP)
	if got := IPv4Protocol(pkt); got != TCP {
		t.Fatalf("IPv4Protocol = %d, want %d (TCP)", got, TCP)
	}
	pkt[9] = byte(UDP)
	if got := IPv4Protocol(pkt); got != UDP {
		t.Fatalf("IPv4Protocol = %d, want %d (UDP)", got, UDP)
	}
	pkt[9] = byte(ICMP)
	if got := IPv4Protocol(pkt); got != ICMP {
		t.Fatalf("IPv4Protocol = %d, want %d (ICMP)", got, ICMP)
	}
}

func TestIPv4Source(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[12], pkt[13], pkt[14], pkt[15] = 192, 168, 1, 1
	got := IPv4Source(pkt)
	if !got.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Fatalf("IPv4Source = %s, want 192.168.1.1", got)
	}
}

func TestSetIPv4Source(t *testing.T) {
	pkt := make([]byte, 20)
	SetIPv4Source(pkt, net.IPv4(10, 0, 0, 5))
	if pkt[12] != 10 || pkt[13] != 0 || pkt[14] != 0 || pkt[15] != 5 {
		t.Fatalf("SetIPv4Source = %d.%d.%d.%d, want 10.0.0.5", pkt[12], pkt[13], pkt[14], pkt[15])
	}
}

func TestIPv4Destination(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[16], pkt[17], pkt[18], pkt[19] = 8, 8, 8, 8
	got := IPv4Destination(pkt)
	if !got.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Fatalf("IPv4Destination = %s, want 8.8.8.8", got)
	}
}

func TestSetIPv4Destination(t *testing.T) {
	pkt := make([]byte, 20)
	SetIPv4Destination(pkt, net.IPv4(1, 2, 3, 4))
	if pkt[16] != 1 || pkt[17] != 2 || pkt[18] != 3 || pkt[19] != 4 {
		t.Fatalf("SetIPv4Destination = %d.%d.%d.%d, want 1.2.3.4", pkt[16], pkt[17], pkt[18], pkt[19])
	}
}

func TestIPv4Payload(t *testing.T) {
	// IHL = 5 (standard 20-byte header)
	pkt := []byte{0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3}
	payload := IPv4Payload(pkt)
	if len(payload) != 3 || payload[0] != 1 || payload[2] != 3 {
		t.Fatalf("IPv4Payload = %v, want [1 2 3]", payload)
	}

	// IHL = 6 (24-byte header with options)
	pkt2 := []byte{0x46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99}
	payload2 := IPv4Payload(pkt2)
	if len(payload2) != 1 || payload2[0] != 99 {
		t.Fatalf("IPv4Payload(IHL=6) = %v, want [99]", payload2)
	}
}

func TestIPv4SourcePort(t *testing.T) {
	// Build a minimal IPv4 header + TCP header
	pkt := make([]byte, 20+2)
	pkt[0] = 0x45 // IHL=5
	// src port = 1234 = 0x04D2
	pkt[20] = 0x04
	pkt[21] = 0xD2
	if got := IPv4SourcePort(pkt); got != 1234 {
		t.Fatalf("IPv4SourcePort = %d, want 1234", got)
	}
}

func TestIPv4DestinationPort(t *testing.T) {
	pkt := make([]byte, 20+4)
	pkt[0] = 0x45 // IHL=5
	// dst port = 443 = 0x01BB
	pkt[22] = 0x01
	pkt[23] = 0xBB
	if got := IPv4DestinationPort(pkt); got != 443 {
		t.Fatalf("IPv4DestinationPort = %d, want 443", got)
	}
}

func TestSetIPv4SourcePort(t *testing.T) {
	pkt := make([]byte, 20+2)
	pkt[0] = 0x45
	SetIPv4SourcePort(pkt, 8080)
	if pkt[20] != 0x1F || pkt[21] != 0x90 {
		t.Fatalf("SetIPv4SourcePort = %x %x, want 1f 90", pkt[20], pkt[21])
	}
}

func TestSetIPv4DestinationPort(t *testing.T) {
	pkt := make([]byte, 20+4)
	pkt[0] = 0x45
	SetIPv4DestinationPort(pkt, 53)
	if pkt[22] != 0x00 || pkt[23] != 0x35 {
		t.Fatalf("SetIPv4DestinationPort = %x %x, want 00 35", pkt[22], pkt[23])
	}
}
