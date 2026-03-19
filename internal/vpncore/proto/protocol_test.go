package proto

import "testing"

func TestHeaderFormat(t *testing.T) {
	if len(Header) != 8 {
		t.Fatalf("Header length = %d, want 8", len(Header))
	}
	if Header[0] != 0x53 || Header[1] != 0x54 || Header[2] != 0x46 || Header[3] != 0x01 {
		t.Fatalf("unexpected CSTP header prefix: %#v", Header[:4])
	}
	if Header[7] != 0x00 {
		t.Fatalf("Header[7] = %#x, want 0x00", Header[7])
	}
}

func TestPayloadTypeConstants(t *testing.T) {
	tests := []struct {
		name string
		got  byte
		want byte
	}{
		{name: "data", got: PayloadData, want: 0x00},
		{name: "dpd request", got: PayloadDPDReq, want: 0x03},
		{name: "dpd response", got: PayloadDPDResp, want: 0x04},
		{name: "disconnect", got: PayloadDisconnect, want: 0x05},
		{name: "keepalive", got: PayloadKeepalive, want: 0x07},
		{name: "compressed", got: PayloadCompressed, want: 0x08},
		{name: "terminate", got: PayloadTerminate, want: 0x09},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Fatalf("%s constant = %#x, want %#x", tt.name, tt.got, tt.want)
		}
	}
}
