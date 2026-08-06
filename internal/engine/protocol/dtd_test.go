package protocol

import (
	"encoding/xml"
	"strings"
	"testing"
)

// fullAuthDoc is a realistic server <config-auth> response in the shape the
// Cisco DTD (draft-mavrogiannopoulos-openconnect-03 appendix C.1) describes,
// exercising every field DTD populates. Kept as a single fixture so the
// "exact frame" happy path asserts the whole schema in one pass.
const fullAuthDoc = `<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
  <version who="vpn">4.10.03106</version>
  <device-id computer-name="CORP-LAPTOP" device-type="linux-64" platform-version="6.12" unique-id="abc-123"/>
  <opaque is-for="sg">
    <tunnel-group>corp-vpn</tunnel-group>
    <auth-method>single-sign-on-v2</auth-method>
    <config-hash>deadbeef</config-hash>
  </opaque>
  <capabilities>
    <auth-method>single-sign-on-v2</auth-method>
    <auth-method>external-browser</auth-method>
  </capabilities>
  <config>
    <opaque>
      <custom-attr>
        <dynamic-split-include-domains>corp.example.com</dynamic-split-include-domains>
        <dynamic-split-exclude-domains>public.example.com</dynamic-split-exclude-domains>
      </custom-attr>
    </opaque>
  </config>
  <session-token>TOKEN-0A1B2C</session-token>
</config-auth>`

func mustUnmarshal(t *testing.T, doc string) DTD {
	t.Helper()
	var d DTD
	if err := xml.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("xml.Unmarshal: %v", err)
	}
	return d
}

func TestDTDUnmarshalFullDocument(t *testing.T) {
	d := mustUnmarshal(t, fullAuthDoc)

	if d.XMLName.Local != "config-auth" {
		t.Fatalf("XMLName.Local = %q, want config-auth", d.XMLName.Local)
	}
	if d.Client != "vpn" || d.Type != "auth-reply" || d.AggregateAuthVersion != "2" {
		t.Fatalf("attrs: client=%q type=%q aggregate-auth-version=%q",
			d.Client, d.Type, d.AggregateAuthVersion)
	}
	if d.Version != "4.10.03106" {
		t.Fatalf("Version = %q", d.Version)
	}
	if d.SessionToken != "TOKEN-0A1B2C" {
		t.Fatalf("SessionToken = %q", d.SessionToken)
	}

	// device-id attributes and children.
	if d.DeviceId.ComputerName != "CORP-LAPTOP" || d.DeviceId.DeviceType != "linux-64" ||
		d.DeviceId.PlatformVersion != "6.12" || d.DeviceId.UniqueId != "abc-123" {
		t.Fatalf("device-id = %+v", d.DeviceId)
	}

	// opaque fields.
	if d.Opaque.TunnelGroup != "corp-vpn" || d.Opaque.AuthMethod != "single-sign-on-v2" ||
		d.Opaque.GroupAlias != "" || d.Opaque.ConfigHash != "deadbeef" {
		t.Fatalf("opaque = %+v", d.Opaque)
	}

	// capabilities, repeated auth-method -> slice.
	if len(d.Capabilities.AuthMethods) != 2 ||
		d.Capabilities.AuthMethods[0] != "single-sign-on-v2" ||
		d.Capabilities.AuthMethods[1] != "external-browser" {
		t.Fatalf("capabilities = %+v", d.Capabilities.AuthMethods)
	}

	// config/opaque/custom-attr: the session.go dynamic-split path.
	if d.Config.Opaque.CustomAttr.DynamicSplitIncludeDomains != "corp.example.com" ||
		d.Config.Opaque.CustomAttr.DynamicSplitExcludeDomains != "public.example.com" {
		t.Fatalf("config custom-attr = %+v", d.Config.Opaque.CustomAttr)
	}
}

// TestDTDUnknownFieldsAreIgnored pins the lenient contract: an unknown-but-well-formed
// element must not fail the parse, and must not corrupt the fields that are known.
func TestDTDUnknownFieldsAreIgnored(t *testing.T) {
	doc := `<config-auth type="unknown"><garbage>ignored</garbage><version>x</version></config-auth>`
	d := mustUnmarshal(t, doc)
	if d.Version != "x" || d.Type != "unknown" {
		t.Fatalf("known fields clobbered by unknown element: %+v", d)
	}
}

// client-cert-request is a flag whose presence the auth package reads via a non-nil
// *struct{} marker; absence must stay nil.
func TestDTDClientCertRequestPresence(t *testing.T) {
	present := mustUnmarshal(t, `<config-auth><client-cert-request/></config-auth>`)
	if present.ClientCertRequest == nil {
		t.Fatal("ClientCertRequest = nil, want non-nil when <client-cert-request/> present")
	}

	absent := mustUnmarshal(t, `<config-auth/>`)
	if absent.ClientCertRequest != nil {
		t.Fatal("ClientCertRequest != nil, want nil when element absent")
	}
}

// form groups map to a []string over select>option, as used by the auth flow.
func TestDTDAuthFormGroupOptions(t *testing.T) {
	doc := `<config-auth type="auth-request">
  <auth>
    <message>Choose a group</message>
    <form action="/+CSCOE+/saml/sp/acs?tgname=corp-vpn">
      <select>
        <option>Engineering</option>
        <option>Marketing</option>
      </select>
    </form>
  </auth>
</config-auth>`
	d := mustUnmarshal(t, doc)

	if d.Type != "auth-request" || d.Auth.Message != "Choose a group" {
		t.Fatalf("auth metadata = type=%q message=%q", d.Type, d.Auth.Message)
	}
	if d.Auth.Form.Action == "" || !strings.Contains(d.Auth.Form.Action, "+CSCOE+") {
		t.Fatalf("form action = %q", d.Auth.Form.Action)
	}
	if len(d.Auth.Form.Groups) != 2 || d.Auth.Form.Groups[0] != "Engineering" ||
		d.Auth.Form.Groups[1] != "Marketing" {
		t.Fatalf("form groups = %+v", d.Auth.Form.Groups)
	}
}

// The auth package reads error text from both top-level <error> and nested
// <auth><error>; both must land in the right field (auth_test.go depends on the
// top-level vs auth-level distinction).
func TestDTDErrorSections(t *testing.T) {
	top := mustUnmarshal(t, `<config-auth>
  <error id="auth" param1="user" param2="password">Invalid credentials.</error>
</config-auth>`)
	if top.Error.ID != "auth" || top.Error.Param1 != "user" || top.Error.Param2 != "password" ||
		top.Error.Value != "Invalid credentials." {
		t.Fatalf("top-level error = %+v", top.Error)
	}

	nested := mustUnmarshal(t, `<config-auth><auth><error id="0">Auth failed.</error></auth></config-auth>`)
	if nested.Auth.Error.ID != "0" || nested.Auth.Error.Value != "Auth failed." {
		t.Fatalf("auth-level error = %+v", nested.Auth.Error)
	}

	// No error element at all must leave both zero-valued, not populated.
	empty := mustUnmarshal(t, `<config-auth/>`)
	if empty.Error.Value != "" || empty.Auth.Error.Value != "" {
		t.Fatalf("empty error fields leaked: top=%+v auth=%+v", empty.Error, empty.Auth.Error)
	}
}

func TestDTDUnmarshalRejectsMalformedXML(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"empty payload", ""},
		{"truncated root", `<config-auth><version>`},
		{"unclosed element", `<config-auth><auth>`},
		{"unmatched close", `<config-auth></version>`},
		{"non-xml", `this is not xml at all <<<`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var d DTD
			if err := xml.Unmarshal([]byte(tc.doc), &d); err == nil {
				t.Fatalf("xml.Unmarshal(%q) = nil error, want error", tc.doc)
			}
		})
	}
}

// encoding/xml.Unmarshal stops at the first root element and ignores anything
// after it. Trailing bytes or a second root therefore do NOT error — they are a
// tolerated stream artifact. Pin that so a future change does not silently make
// the parser strict (or looser) here.
func TestDTDUnmarshalToleratesTrailingContent(t *testing.T) {
	for _, doc := range []string{`<config-auth/>garbage`, `<config-auth/><config-auth/>`} {
		var d DTD
		if err := xml.Unmarshal([]byte(doc), &d); err != nil {
			t.Fatalf("xml.Unmarshal(%q) = %v, want nil (lenient trailing content)", doc, err)
		}
	}
}
