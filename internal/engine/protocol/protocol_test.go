package protocol

import (
	"encoding/xml"
	"testing"
)

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

func TestDTDUnmarshal(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
	<version>4.10.07062</version>
	<group-access>https://vpn.example.com/group</group-access>
	<session-token>abc123token</session-token>
	<auth>
		<username>testuser</username>
		<password>secret</password>
		<message>Authenticating...</message>
		<form action="/auth">
			<select>
				<option>Engineering</option>
				<option>Sales</option>
			</select>
		</form>
	</auth>
	<config>
		<opaque>
			<custom-attr>
				<dynamic-split-exclude-domains>exclude.example.com</dynamic-split-exclude-domains>
				<dynamic-split-include-domains>include.example.com</dynamic-split-include-domains>
			</custom-attr>
		</opaque>
	</config>
	<device-id computer-name="laptop" device-type="linux" platform-version="1.0" unique-id="uuid-123" unique-id-global="uuid-global-456"/>
</config-auth>`

	var dtd DTD
	if err := xml.Unmarshal([]byte(input), &dtd); err != nil {
		t.Fatalf("Unmarshal DTD: %v", err)
	}

	if dtd.Client != "vpn" {
		t.Fatalf("Client = %q, want %q", dtd.Client, "vpn")
	}
	if dtd.Type != "init" {
		t.Fatalf("Type = %q, want %q", dtd.Type, "init")
	}
	if dtd.AggregateAuthVersion != "2" {
		t.Fatalf("AggregateAuthVersion = %q, want %q", dtd.AggregateAuthVersion, "2")
	}
	if dtd.Version != "4.10.07062" {
		t.Fatalf("Version = %q, want %q", dtd.Version, "4.10.07062")
	}
	if dtd.GroupAccess != "https://vpn.example.com/group" {
		t.Fatalf("GroupAccess = %q, want %q", dtd.GroupAccess, "https://vpn.example.com/group")
	}
	if dtd.SessionToken != "abc123token" {
		t.Fatalf("SessionToken = %q, want %q", dtd.SessionToken, "abc123token")
	}

	// Auth fields
	if dtd.Auth.Username != "testuser" {
		t.Fatalf("Auth.Username = %q, want %q", dtd.Auth.Username, "testuser")
	}
	if dtd.Auth.Password != "secret" {
		t.Fatalf("Auth.Password = %q, want %q", dtd.Auth.Password, "secret")
	}
	if dtd.Auth.Message != "Authenticating..." {
		t.Fatalf("Auth.Message = %q, want %q", dtd.Auth.Message, "Authenticating...")
	}
	if dtd.Auth.Form.Action != "/auth" {
		t.Fatalf("Auth.Form.Action = %q, want %q", dtd.Auth.Form.Action, "/auth")
	}
	if len(dtd.Auth.Form.Groups) != 2 || dtd.Auth.Form.Groups[0] != "Engineering" || dtd.Auth.Form.Groups[1] != "Sales" {
		t.Fatalf("Auth.Form.Groups = %v, want [Engineering Sales]", dtd.Auth.Form.Groups)
	}

	// Config -> opaque -> custom-attr
	if dtd.Config.Opaque.CustomAttr.DynamicSplitExcludeDomains != "exclude.example.com" {
		t.Fatalf("DynamicSplitExcludeDomains = %q, want %q", dtd.Config.Opaque.CustomAttr.DynamicSplitExcludeDomains, "exclude.example.com")
	}
	if dtd.Config.Opaque.CustomAttr.DynamicSplitIncludeDomains != "include.example.com" {
		t.Fatalf("DynamicSplitIncludeDomains = %q, want %q", dtd.Config.Opaque.CustomAttr.DynamicSplitIncludeDomains, "include.example.com")
	}

	// Device ID fields
	if dtd.DeviceId.ComputerName != "laptop" {
		t.Fatalf("DeviceId.ComputerName = %q, want %q", dtd.DeviceId.ComputerName, "laptop")
	}
	if dtd.DeviceId.DeviceType != "linux" {
		t.Fatalf("DeviceId.DeviceType = %q, want %q", dtd.DeviceId.DeviceType, "linux")
	}
	if dtd.DeviceId.PlatformVersion != "1.0" {
		t.Fatalf("DeviceId.PlatformVersion = %q, want %q", dtd.DeviceId.PlatformVersion, "1.0")
	}
	if dtd.DeviceId.UniqueId != "uuid-123" {
		t.Fatalf("DeviceId.UniqueId = %q, want %q", dtd.DeviceId.UniqueId, "uuid-123")
	}
	if dtd.DeviceId.UniqueIdGlobal != "uuid-global-456" {
		t.Fatalf("DeviceId.UniqueIdGlobal = %q, want %q", dtd.DeviceId.UniqueIdGlobal, "uuid-global-456")
	}
}

func TestDTDErrorParsing(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth type="auth-reply">
	<auth>
		<error id="52473434" param1="vpn.example.com" param2="">Authentication failed.</error>
	</auth>
</config-auth>`

	var dtd DTD
	if err := xml.Unmarshal([]byte(input), &dtd); err != nil {
		t.Fatalf("Unmarshal DTD error: %v", err)
	}

	if dtd.Auth.Error.ID != "52473434" {
		t.Fatalf("Auth.Error.ID = %q, want %q", dtd.Auth.Error.ID, "52473434")
	}
	if dtd.Auth.Error.Param1 != "vpn.example.com" {
		t.Fatalf("Auth.Error.Param1 = %q, want %q", dtd.Auth.Error.Param1, "vpn.example.com")
	}
	if dtd.Auth.Error.Value != "Authentication failed." {
		t.Fatalf("Auth.Error.Value = %q, want %q", dtd.Auth.Error.Value, "Authentication failed.")
	}
}

func TestDTDOpaque(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth type="auth-reply">
	<opaque>
		<tunnel-group>Engineering</tunnel-group>
		<auth-method>password</auth-method>
		<group-alias>eng-team</group-alias>
		<config-hash>abc123</config-hash>
	</opaque>
</config-auth>`

	var dtd DTD
	if err := xml.Unmarshal([]byte(input), &dtd); err != nil {
		t.Fatalf("Unmarshal DTD opaque: %v", err)
	}

	if dtd.Opaque.TunnelGroup != "Engineering" {
		t.Fatalf("Opaque.TunnelGroup = %q, want %q", dtd.Opaque.TunnelGroup, "Engineering")
	}
	if dtd.Opaque.AuthMethod != "password" {
		t.Fatalf("Opaque.AuthMethod = %q, want %q", dtd.Opaque.AuthMethod, "password")
	}
	if dtd.Opaque.GroupAlias != "eng-team" {
		t.Fatalf("Opaque.GroupAlias = %q, want %q", dtd.Opaque.GroupAlias, "eng-team")
	}
	if dtd.Opaque.ConfigHash != "abc123" {
		t.Fatalf("Opaque.ConfigHash = %q, want %q", dtd.Opaque.ConfigHash, "abc123")
	}
}

func TestDTDCapabilities(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth type="auth-reply">
	<capabilities>
		<auth-method>password</auth-method>
		<auth-method>certificate</auth-method>
		<auth-method>token</auth-method>
	</capabilities>
</config-auth>`

	var dtd DTD
	if err := xml.Unmarshal([]byte(input), &dtd); err != nil {
		t.Fatalf("Unmarshal DTD capabilities: %v", err)
	}

	if len(dtd.Capabilities.AuthMethods) != 3 {
		t.Fatalf("capabilities count = %d, want 3", len(dtd.Capabilities.AuthMethods))
	}
	if dtd.Capabilities.AuthMethods[0] != "password" {
		t.Fatalf("AuthMethods[0] = %q, want %q", dtd.Capabilities.AuthMethods[0], "password")
	}
	if dtd.Capabilities.AuthMethods[2] != "token" {
		t.Fatalf("AuthMethods[2] = %q, want %q", dtd.Capabilities.AuthMethods[2], "token")
	}
}

func TestDTDClientCertRequest(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth type="auth-reply">
	<client-cert-request/>
</config-auth>`

	var dtd DTD
	if err := xml.Unmarshal([]byte(input), &dtd); err != nil {
		t.Fatalf("Unmarshal client-cert-request: %v", err)
	}

	if dtd.ClientCertRequest == nil {
		t.Fatal("expected ClientCertRequest to be non-nil")
	}
}

func TestDTDEmptyMacAddress(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth type="auth-reply">
	<mac-address-list>
		<mac-address>00:11:22:33:44:55</mac-address>
	</mac-address-list>
</config-auth>`

	var dtd DTD
	if err := xml.Unmarshal([]byte(input), &dtd); err != nil {
		t.Fatalf("Unmarshal mac-address-list: %v", err)
	}

	if dtd.MacAddressList.MacAddress != "00:11:22:33:44:55" {
		t.Fatalf("MacAddress = %q, want %q", dtd.MacAddressList.MacAddress, "00:11:22:33:44:55")
	}
}

func TestPayloadStructLayout(t *testing.T) {
	pl := Payload{Type: PayloadData, Data: []byte{1, 2, 3}}
	if pl.Type != PayloadData {
		t.Fatalf("Type = %#x, want %#x", pl.Type, PayloadData)
	}
	if len(pl.Data) != 3 || pl.Data[0] != 1 {
		t.Fatalf("Data = %v, want [1 2 3]", pl.Data)
	}
}
