package dnsq

import (
	"strings"
	"testing"
)

func TestParseName(t *testing.T) {
	cases := []struct {
		in      string
		name    string
		display string
		reverse bool
	}{
		{"Example.COM", "example.com", "example.com", false},
		{"https://example.com/path?q=1", "example.com", "example.com", false},
		{"_dmarc.example.com.", "_dmarc.example.com", "_dmarc.example.com", false},
		{"_acme-challenge.example.com", "_acme-challenge.example.com", "_acme-challenge.example.com", false},
		{"*.example.com", "*.example.com", "*.example.com", false},
		{"1.2.3.4", "4.3.2.1.in-addr.arpa", "1.2.3.4", true},
		{"[2001:db8::1]", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::1", true},
	}
	for _, tc := range cases {
		got, err := ParseName(tc.in)
		if err != nil {
			t.Fatalf("ParseName(%q) error: %v", tc.in, err)
		}
		if got.Name != tc.name || got.Display != tc.display || got.Reverse != tc.reverse {
			t.Errorf("ParseName(%q) = %+v, want name %s display %s reverse %v", tc.in, got, tc.name, tc.display, tc.reverse)
		}
	}
}

func TestParseNameRejects(t *testing.T) {
	for _, in := range []string{"", " ", "not a name", "exa mple.com", "-bad.example", strings.Repeat("a", 64) + ".com"} {
		if _, err := ParseName(in); err == nil {
			t.Errorf("ParseName(%q) succeeded", in)
		}
	}
}

func TestValidateServer(t *testing.T) {
	if got, err := ValidateServer("8.8.8.8"); err != nil || got != "8.8.8.8" {
		t.Fatalf("public v4: %q %v", got, err)
	}
	if got, err := ValidateServer("[2001:4860:4860::8888]"); err != nil || got != "2001:4860:4860::8888" {
		t.Fatalf("public v6: %q %v", got, err)
	}
	if _, err := ValidateServer("DNS.Google"); err != nil || false {
		// hostname is accepted; resolution happens later
	}
	got, err := ValidateServer("DNS.Google")
	if err != nil || got != "dns.google" {
		t.Fatalf("hostname: %q %v", got, err)
	}
	for _, bad := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.1.1", "0.0.0.0", "192.0.2.1", "100.64.0.1", "[::1]", "8.8.8.8:443", ""} {
		if _, err := ValidateServer(bad); err == nil {
			t.Errorf("ValidateServer(%q) succeeded", bad)
		}
	}
}
