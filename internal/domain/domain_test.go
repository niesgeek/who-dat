package domain

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantASCII   string
		wantTLD     string
		wantUnicode string // "" means expect equal to ASCII (not an IDN)
	}{
		{"plain", "example.com", "example.com", "com", ""},
		{"full url with www", "https://www.Example.com/path?q=1", "example.com", "com", ""},
		{"subdomain", "a.b.example.co.uk", "example.co.uk", "co.uk", ""},
		{"trailing dot", "example.com.", "example.com", "com", ""},
		{"port and creds", "user:pass@example.com:8080", "example.com", "com", ""},
		{"uppercase", "EXAMPLE.COM", "example.com", "com", ""},
		{"idn unicode", "bücher.de", "xn--bcher-kva.de", "de", "bücher.de"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.in, err)
			}
			if got.ASCII != tt.wantASCII {
				t.Errorf("ASCII = %q, want %q", got.ASCII, tt.wantASCII)
			}
			if got.TLD != tt.wantTLD {
				t.Errorf("TLD = %q, want %q", got.TLD, tt.wantTLD)
			}
			wantUni := tt.wantUnicode
			if wantUni == "" {
				wantUni = tt.wantASCII
			}
			if got.Unicode != wantUni {
				t.Errorf("Unicode = %q, want %q", got.Unicode, wantUni)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"empty", "", ErrInvalidDomain},
		{"whitespace", "   ", ErrInvalidDomain},
		{"bare tld", "com", ErrNoPublicSuffix},
		{"suffix only", "co.uk", ErrNoPublicSuffix},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Parse(%q) err = %v, want %v", tt.in, err, tt.wantErr)
			}
		})
	}
}

// TestParsePlatformNamespace: names inside a platform-run namespace must fail
// with the platform attached, never collapse into a lookup of the parent
// (which would misreport the name as unregistered).
func TestParsePlatformNamespace(t *testing.T) {
	tests := []struct {
		in       string
		platform string
	}{
		{"foo.cc.cd", "DNSHE"},
		{"a.b.us.ci", "DNSHE"},
		{"x.de5.net", "DNSHE"},
		{"myname.owo.name", "FurryBox"},
		{"site.xwx.me", "FurryBox"},
		{"hello.loc.cc", "Yunamo"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			_, err := Parse(tt.in)
			var pe *PlatformNamespaceError
			if !errors.As(err, &pe) {
				t.Fatalf("Parse(%q) err = %v, want PlatformNamespaceError", tt.in, err)
			}
			if pe.Namespace.Name != tt.platform {
				t.Errorf("platform = %q, want %q", pe.Namespace.Name, tt.platform)
			}
			if pe.Namespace.URL == "" || pe.Namespace.Suffix == "" {
				t.Errorf("platform info incomplete: %+v", pe.Namespace)
			}
		})
	}
}

func TestParsePlatformParentIsNormal(t *testing.T) {
	// The parent domain itself is a registry record, not a platform name.
	for _, in := range []string{"cc.cd", "owo.name", "de5.net"} {
		if _, err := Parse(in); err != nil {
			var pe *PlatformNamespaceError
			if errors.As(err, &pe) {
				t.Errorf("Parse(%q) wrongly flagged as platform namespace", in)
			}
		}
	}
}
