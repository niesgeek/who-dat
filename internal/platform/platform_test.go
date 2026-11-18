package platform

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lissy93/who-dat/internal/dnsq"
	"github.com/lissy93/who-dat/internal/domain"
	"github.com/lissy93/who-dat/internal/model"
)

// live fixtures, shapes verified 2026-11-18 against the platforms' own APIs
// (FurryBox text endpoint direct; SEUS direct against https://s.eus/api/whois).
const furryFound = `% whois.furry.box
% Query: nic.owo.name

Domain Name:      nic.owo.name
Registry:         FurryBox
Suffix:           owo.name
Status:           permanent
Created:          2026-10-29 14:44:43 UTC
Expires:          never (permanent)
DNS Records:      0
Name Servers:     ns1.furrydns.com
                  ns2.furrydns.com
                  (FurryBox default)

Registrant:       f****m@hotmail.com
% Contact disclosed by the owner (masked).

% Queried at 2026-11-18 02:06:35 UTC
% https://www.furry.box/whois
`

const furryNotFound = `% whois.furry.box
% Query: zzz.owo.name

Domain not registered.

% The suffix belongs to FurryBox, this name is available.
`

const furryNotOurs = `% whois.furry.box
% Query: example.com

Domain not found.

% This service only covers domains registered with FurryBox.
`

const seusFound = `{"state":"found","fqdn":"domain.fs.kg","fields":[
{"k":"Domain Name","v":"domain.fs.kg"},
{"k":"Registrar","v":"SEUS Community"},
{"k":"Registrar URL","v":"https://s.eus"},
{"k":"Creation Date","v":"2026-11-15"},
{"k":"Updated Date","v":"2026-11-15"},
{"k":"Registry Expiry Date","v":"2029-11-15"},
{"k":"Domain Status","v":"ok"},
{"k":"Registrant Name","v":"Carter Alex"},
{"k":"Registrant Email","v":"","img":"data:image/svg+xml;base64,AAAA"},
{"k":"Nameserver","v":"a.ns.fs5.net"},
{"k":"Nameserver","v":"b.ns.fs5.net"},
{"k":"DNSSEC","v":"unsigned"}]}`

const seusNotFound = `{"state":"not_found","fqdn":"zzz.fs.kg","fields":[]}`

func TestFurryFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/nic.owo.name" {
			t.Errorf("path = %s, want /nic.owo.name", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(furryFound))
	}))
	defer ts.Close()

	c := NewFurryClient(ts.Client())
	c.endpoint = ts.URL + "/"
	n, _ := domain.Parse("nic.owo.name")
	res, err := c.Lookup(context.Background(), n, "owo.name")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !res.IsRegistered || res.Meta.Source != model.SourcePlatform {
		t.Errorf("result = %+v, want registered platform result", res)
	}
	if res.Platform == nil || res.Platform.Name != "FurryBox" || res.Platform.Suffix != "owo.name" {
		t.Errorf("platform = %+v", res.Platform)
	}
	if !res.Permanent || res.Dates.Expires != nil {
		t.Errorf("permanent = %v expires = %v, want permanent with no expiry", res.Permanent, res.Dates.Expires)
	}
	if res.Dates.Created == nil || res.Dates.Created.Format("2006-01-02") != "2026-10-29" {
		t.Errorf("created = %v", res.Dates.Created)
	}
	if len(res.Nameservers) != 2 || res.Nameservers[0].Name != "ns1.furrydns.com" {
		t.Errorf("nameservers = %+v", res.Nameservers)
	}
	if res.Contacts.Registrant.Email == nil || *res.Contacts.Registrant.Email != "f****m@hotmail.com" {
		t.Errorf("registrant email = %+v", res.Contacts.Registrant.Email)
	}
	if len(res.Raw) == 0 || res.RawContentType == "" {
		t.Errorf("raw payload missing")
	}
}

func TestFurryNotFoundAndRateLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/limited"):
			w.WriteHeader(http.StatusTooManyRequests)
		case r.URL.Path == "/example.com":
			w.Write([]byte(furryNotOurs))
		default:
			w.Write([]byte(furryNotFound))
		}
	}))
	defer ts.Close()

	c := NewFurryClient(ts.Client())
	c.endpoint = ts.URL + "/"
	n, _ := domain.Parse("zzz.owo.name")
	_, err := c.Lookup(context.Background(), n, "owo.name")
	var nf *NotFound
	if !errors.As(err, &nf) {
		t.Fatalf("Lookup err = %v, want *NotFound", err)
	}
	if nf.Provider != "FurryBox" || nf.Reason != "NOT_REGISTERED" {
		t.Errorf("notfound = %+v", nf)
	}

	n2, _ := domain.Parse("example.com")
	_, err = c.Lookup(context.Background(), n2, "")
	if !errors.As(err, &nf) || nf.Reason != "NOT_OURS" {
		t.Fatalf("Lookup(example.com) err = %v, want *NotFound NOT_OURS", err)
	}

	c.endpoint = ts.URL + "/limited"
	_, err = c.Lookup(context.Background(), n, "owo.name")
	if err == nil {
		t.Fatalf("limited Lookup err = nil, want rate limited")
	}
}

func TestSeusFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("domain") != "domain.fs.kg" {
			t.Errorf("domain = %q", r.URL.Query().Get("domain"))
		}
		w.Write([]byte(seusFound))
	}))
	defer ts.Close()

	c := NewSeusClient(ts.Client())
	c.endpoint = ts.URL
	n, _ := domain.Parse("domain.fs.kg")
	res, err := c.Lookup(context.Background(), n, "fs.kg")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !res.IsRegistered || res.Meta.Source != model.SourcePlatform {
		t.Errorf("result = %+v", res)
	}
	if res.Platform == nil || res.Platform.Name != "SEUS" || res.Platform.Suffix != "fs.kg" {
		t.Errorf("platform = %+v", res.Platform)
	}
	if res.Dates.Created == nil || res.Dates.Created.Format("2006-01-02") != "2026-11-15" {
		t.Errorf("created = %v", res.Dates.Created)
	}
	if res.Dates.Expires == nil || res.Dates.Expires.Format("2006-01-02") != "2029-11-15" {
		t.Errorf("expires = %v", res.Dates.Expires)
	}
	if len(res.Nameservers) != 2 {
		t.Errorf("nameservers = %+v", res.Nameservers)
	}
	if res.Contacts.Registrant.Name == nil || *res.Contacts.Registrant.Name != "Carter Alex" {
		t.Errorf("registrant = %+v", res.Contacts.Registrant)
	}
	if res.Contacts.Registrant.Email != nil {
		t.Errorf("registrant email = %v, want nil (img-protected, never rendered)", res.Contacts.Registrant.Email)
	}
	if res.DNSSEC.Signed {
		t.Errorf("dnssec signed = true, want false (unsigned)")
	}
	if len(res.Raw) == 0 {
		t.Errorf("raw payload missing")
	}

	c2 := NewSeusClient(ts.Client())
	c2.endpoint = ts.URL
	// not-found path: the same server answers not_found for any other domain
	n2, _ := domain.Parse("zzz.fs.kg")
	// swap the handler response by re-pointing at a not-found server
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(seusNotFound))
	}))
	defer ts2.Close()
	c2.endpoint = ts2.URL
	_, err = c2.Lookup(context.Background(), n2, "fs.kg")
	var nf *NotFound
	if !errors.As(err, &nf) || nf.Provider != "SEUS" {
		t.Fatalf("Lookup err = %v, want SEUS *NotFound", err)
	}
}

func TestSeusDirectory(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"enabled":true,"suffixes":[{"suffix":"fs.kg","enabled":true},{"suffix":"bg5.net","enabled":true},{"suffix":"old.example","enabled":false}]}`))
	}))
	defer ts.Close()

	d := NewSeusDirectory(ts.Client())
	d.endpoint = ts.URL
	if suf, ok := d.SuffixFor(context.Background(), "domain.fs.kg"); !ok || suf != "fs.kg" {
		t.Errorf("SuffixFor(domain.fs.kg) = %q, %v", suf, ok)
	}
	if _, ok := d.SuffixFor(context.Background(), "x.old.example"); ok {
		t.Errorf("SuffixFor(x.old.example) matched a disabled suffix")
	}
	if _, ok := d.SuffixFor(context.Background(), "fs.kg"); ok {
		t.Errorf("SuffixFor(fs.kg) matched the parent itself")
	}
}

type fakeQuerier struct {
	resp *dnsq.Response
	err  error
}

func (f fakeQuerier) Query(_ context.Context, _ dnsq.Query) (*dnsq.Response, error) {
	return f.resp, f.err
}

func TestRouterDNSLive(t *testing.T) {
	furryTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(furryNotFound))
	}))
	defer furryTS.Close()

	furry := NewFurryClient(furryTS.Client())
	furry.endpoint = furryTS.URL + "/"

	// NS answers exist: the miss is live in DNS.
	live := NewRouter(furry, nil, nil, fakeQuerier{resp: &dnsq.Response{Rcode: "NOERROR", Answer: []dnsq.RR{{Name: "zzz.owo.name"}}}})
	n, _ := domain.Parse("zzz.owo.name")
	_, err := live.Lookup(context.Background(), n)
	var nf *NotFound
	if !errors.As(err, &nf) || nf.DNSLive == nil || !*nf.DNSLive {
		t.Fatalf("Lookup err = %v, want NotFound with DNSLive=true", err)
	}

	// No answers and NXDOMAIN: provably not live.
	dead := NewRouter(furry, nil, nil, fakeQuerier{resp: &dnsq.Response{Rcode: "NXDOMAIN"}})
	_, err = dead.Lookup(context.Background(), n)
	if !errors.As(err, &nf) || nf.DNSLive == nil || *nf.DNSLive {
		t.Fatalf("Lookup err = %v, want NotFound with DNSLive=false", err)
	}

	// DNS error: unknown, not false.
	unknown := NewRouter(furry, nil, nil, fakeQuerier{err: errors.New("boom")})
	_, err = unknown.Lookup(context.Background(), n)
	if !errors.As(err, &nf) || nf.DNSLive != nil {
		t.Fatalf("Lookup err = %v, want NotFound with DNSLive=nil", err)
	}

	// A plain registry name passes through untouched.
	plain := NewRouter(furry, nil, nil, fakeQuerier{})
	n2, _ := domain.Parse("example.com")
	res, err := plain.Lookup(context.Background(), n2)
	if err != nil || res != nil {
		t.Errorf("Lookup(example.com) = %v, %v, want (nil, nil)", res, err)
	}
}
