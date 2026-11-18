package rdap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSeedsAreSane(t *testing.T) {
	for tld, urls := range seeds {
		if tld != strings.ToLower(tld) || len(urls) == 0 {
			t.Errorf("seed %q: TLDs are lowercase and need at least one URL", tld)
		}
		for _, u := range urls {
			if !strings.HasPrefix(u, "https://") || !strings.HasSuffix(u, "/") {
				t.Errorf("seed %q: %q must be https and end with /", tld, u)
			}
		}
	}
	for tld, urls := range overrides {
		if tld != strings.ToLower(tld) || len(urls) == 0 {
			t.Errorf("override %q: TLDs are lowercase and need at least one URL", tld)
		}
		for _, u := range urls {
			if !strings.HasPrefix(u, "https://") || !strings.HasSuffix(u, "/") {
				t.Errorf("override %q: %q must be https and end with /", tld, u)
			}
		}
	}
	for suffix, urls := range suffixSeeds {
		if suffix != strings.ToLower(suffix) || len(urls) == 0 {
			t.Errorf("suffix seed %q: suffixes are lowercase and need at least one URL", suffix)
		}
		for _, u := range urls {
			if !strings.HasPrefix(u, "https://") || !strings.HasSuffix(u, "/") {
				t.Errorf("suffix seed %q: %q must be https and end with /", suffix, u)
			}
		}
	}
}

func TestBootstrapSeeds(t *testing.T) {
	// Fake IANA registry: knows com, and claims ch (so the seed must lose)
	// and kg over http (so the https override must win).
	iana := `{"services":[[["com"],["https://rdap.verisign.com/com/v1/"]],[["ch"],["https://iana.example/"]],[["kg"],["http://rdap.cctld.kg/"]]]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(iana))
	}))
	defer ts.Close()

	b := newBootstrap(ts.Client())
	b.url = ts.URL

	tests := []struct{ domain, want string }{
		{"vaduz.li", "https://rdap.nic.li/"},                 // seed fills the gap
		{"nic.ch", "https://iana.example/"},                  // IANA outranks the seed
		{"example.com", "https://rdap.verisign.com/com/v1/"}, // business as usual
		{"example.co.lu", "https://rdap.cctld.com/"},         // second-level suffix seed
		{"example.wz.org", "https://rdap.cctld.com/"},        // second-level suffix seed
		{"example.qa", "https://rdap.registry.qa/rdap/"},     // seed fills the gap (IANA lists no RDAP for .qa)
		{"example.kg", "https://rdap.cctld.kg/"},             // override beats IANA's http entry
	}
	for _, tt := range tests {
		urls, err := b.serversFor(context.Background(), tt.domain)
		if err != nil {
			t.Fatalf("%s: %v", tt.domain, err)
		}
		if urls[0] != tt.want {
			t.Errorf("%s = %q, want %q", tt.domain, urls[0], tt.want)
		}
	}
}
