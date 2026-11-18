package whois

import "testing"

func TestWhoisServersFor(t *testing.T) {
	tests := []struct {
		in   string
		want string // "" means no override: the library picks the server
	}{
		{"example.pp.ua", "whois.pp.ua"},
		{"a.b.pp.ua", "whois.pp.ua"},
		{"pp.ua", ""},       // the parent itself is a normal .ua name
		{"example.ua", ""},  // plain .ua: library default
		{"example.com", ""}, // unrelated TLD
		{"notpp.ua", ""},    // must not match the suffix check
	}
	for _, tt := range tests {
		got := whoisServersFor(tt.in)
		if tt.want == "" {
			if len(got) != 0 {
				t.Errorf("whoisServersFor(%q) = %v, want no override", tt.in, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != tt.want {
			t.Errorf("whoisServersFor(%q) = %v, want [%s]", tt.in, got, tt.want)
		}
	}
}
