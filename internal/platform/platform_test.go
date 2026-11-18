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
	"github.com/lissy93/who-dat/internal/srcerr"
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

const furryActive = `% whois.furry.box
% Query: z.site.tv

Domain Name:      z.site.tv
Registry:         FurryBox
Suffix:           site.tv
Status:           active
Created:          2026-11-14 17:13:59 UTC
Expires:          2027-11-14 17:13:59 UTC
DNS Records:      0
Name Servers:     ns1.furrydns.com
                  ns2.furrydns.com
                  (FurryBox default)

Registrant:       not disclosed
% The owner has not opted in to WHOIS disclosure.

% Queried at 2026-11-18 02:24:19 UTC
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

// TestFurryActive covers a normal (non-permanent) record: an expiry date and
// a Registrant line that is not an address ("not disclosed") must not be
// stored as an email.
func TestFurryActive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(furryActive))
	}))
	defer ts.Close()

	c := NewFurryClient(ts.Client())
	c.endpoint = ts.URL + "/"
	n, _ := domain.Parse("z.site.tv")
	res, err := c.Lookup(context.Background(), n, "site.tv")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !res.IsRegistered || res.Permanent {
		t.Errorf("registered = %v permanent = %v, want registered non-permanent", res.IsRegistered, res.Permanent)
	}
	if res.Status[0] != "active" {
		t.Errorf("status = %v, want [active]", res.Status)
	}
	if res.Dates.Expires == nil || res.Dates.Expires.Format("2006-01-02") != "2027-11-14" {
		t.Errorf("expires = %v, want 2027-11-14", res.Dates.Expires)
	}
	if res.Contacts.Registrant.Email != nil || !res.Contacts.Registrant.Redacted {
		t.Errorf("registrant = %+v, want no email and redacted", res.Contacts.Registrant)
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

func TestYunamoFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/example.loc.cc") {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(yunamoFound))
	}))
	defer ts.Close()

	c := NewYunamoClient(ts.Client())
	c.endpoint = ts.URL + "/"
	n, _ := domain.Parse("example.loc.cc")
	res, err := c.Lookup(context.Background(), n, "loc.cc")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !res.IsRegistered || res.Meta.Source != model.SourcePlatform {
		t.Errorf("result = %+v", res)
	}
	if res.Platform == nil || res.Platform.Name != "Yunamo" || res.Platform.Suffix != "loc.cc" {
		t.Errorf("platform = %+v", res.Platform)
	}
	if res.Dates.Created == nil || res.Dates.Created.Format("2006-01-02") != "2026-10-20" {
		t.Errorf("created = %v", res.Dates.Created)
	}
	// A 100-year term: the expiry is the story here, not a typo.
	if res.Dates.Expires == nil || res.Dates.Expires.Format("2006-01-02") != "2126-10-20" {
		t.Errorf("expires = %v", res.Dates.Expires)
	}
	if len(res.Status) != 1 || res.Status[0] != "active" {
		t.Errorf("status = %v", res.Status)
	}
	if len(res.Nameservers) != 2 || res.Nameservers[0].Name != "dns1.serv00.com" {
		t.Errorf("nameservers = %+v", res.Nameservers)
	}
	if res.Registrar.Name == nil || *res.Registrar.Name != "Yunamo" {
		t.Errorf("registrar = %+v", res.Registrar)
	}
	if len(res.Events) != 2 {
		t.Errorf("events = %d, want registration + expiration", len(res.Events))
	}
	// Raw is the platform reply verbatim, scan block included.
	if !strings.Contains(string(res.Raw), `"overall_health":"healthy"`) {
		t.Errorf("raw payload missing scan block: %s", res.Raw)
	}
	if res.RawContentType != "application/json" {
		t.Errorf("raw content type = %q", res.RawContentType)
	}
}

func TestYunamoNotFoundAndRateLimited(t *testing.T) {
	nfTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"Domain not found"}`))
	}))
	defer nfTS.Close()
	c := NewYunamoClient(nfTS.Client())
	c.endpoint = nfTS.URL + "/"
	n, _ := domain.Parse("zzzqqq12345notexist.loc.cc")
	_, err := c.Lookup(context.Background(), n, "loc.cc")
	var nf *NotFound
	if !errors.As(err, &nf) || nf.Provider != "Yunamo" || nf.Suffix != "loc.cc" {
		t.Fatalf("Lookup err = %v, want Yunamo *NotFound", err)
	}

	rlTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer rlTS.Close()
	c2 := NewYunamoClient(rlTS.Client())
	c2.endpoint = rlTS.URL + "/"
	_, err = c2.Lookup(context.Background(), n, "loc.cc")
	var rl *srcerr.RateLimited
	if !errors.As(err, &rl) {
		t.Fatalf("Lookup err = %v, want *RateLimited", err)
	}
}

func TestYunamoDirectory(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"root_domains":[{"domain":"loc.cc","is_active":true,"registration_count":13536},{"domain":"vvpp.cc","is_active":true,"registration_count":1},{"domain":"dead.example","is_active":false}]}`))
	}))
	defer ts.Close()

	d := NewYunamoDirectory(ts.Client())
	d.endpoint = ts.URL
	if suf, ok := d.SuffixFor(context.Background(), "example.loc.cc"); !ok || suf != "loc.cc" {
		t.Errorf("SuffixFor(example.loc.cc) = %q, %v", suf, ok)
	}
	if suf, ok := d.SuffixFor(context.Background(), "x.vvpp.cc"); !ok || suf != "vvpp.cc" {
		t.Errorf("SuffixFor(x.vvpp.cc) = %q, %v", suf, ok)
	}
	if _, ok := d.SuffixFor(context.Background(), "x.dead.example"); ok {
		t.Errorf("SuffixFor(x.dead.example) matched an inactive root domain")
	}
	if _, ok := d.SuffixFor(context.Background(), "loc.cc"); ok {
		t.Errorf("SuffixFor(loc.cc) matched the parent itself")
	}
}

func TestRouterYunamo(t *testing.T) {
	yuTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(yunamoFound))
	}))
	defer yuTS.Close()
	dirTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"root_domains":[{"domain":"loc.cc","is_active":true},{"domain":"vvpp.cc","is_active":true}]}`))
	}))
	defer dirTS.Close()

	yu := NewYunamoClient(yuTS.Client())
	yu.endpoint = yuTS.URL + "/"
	ydir := NewYunamoDirectory(dirTS.Client())
	ydir.endpoint = dirTS.URL
	r := NewRouter(nil, nil, nil, yu, ydir, fakeQuerier{})

	n, _ := domain.Parse("example.loc.cc")
	res, err := r.Lookup(context.Background(), n)
	if err != nil || res == nil || res.Platform == nil || res.Platform.Name != "Yunamo" {
		t.Fatalf("Lookup(example.loc.cc) = %+v, %v", res, err)
	}
	n2, _ := domain.Parse("x.vvpp.cc")
	res, err = r.Lookup(context.Background(), n2)
	if err != nil || res == nil {
		t.Fatalf("Lookup(x.vvpp.cc) = %+v, %v", res, err)
	}
	// A plain registry name passes through untouched.
	n3, _ := domain.Parse("example.com")
	res, err = r.Lookup(context.Background(), n3)
	if err != nil || res != nil {
		t.Fatalf("Lookup(example.com) = %+v, %v, want passthrough", res, err)
	}
}

// yunamoFound is the verbatim reply for example.loc.cc (public platform data,
// no personal information), captured 2026-11-18.
const yunamoFound = `{"days_until_deletion":null,"days_until_suspension":null,"downtime_paused_at":null,"expires_at":"2126-10-20T12:11:52.583948Z","first_failed_at":null,"full_domain":"example.loc.cc","nameservers":["dns1.serv00.com","dns2.serv00.com"],"registered_at":"2026-10-20T12:11:52.583948Z","scan":{"dns_status":"resolved","http_status":"online","last_scanned_at":"2026-11-18T01:03:45.804632Z","overall_health":"healthy","safe_browsing_status":"safe","ssl_status":"valid","successful_scans":281,"total_scans":436,"uptime_percentage":64.44954128440367,"virustotal_status":"clean"},"status":"active","suspend_reason":null,"suspended_at":null}`

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
	live := NewRouter(furry, nil, nil, nil, nil, fakeQuerier{resp: &dnsq.Response{Rcode: "NOERROR", Answer: []dnsq.RR{{Name: "zzz.owo.name"}}}})
	n, _ := domain.Parse("zzz.owo.name")
	_, err := live.Lookup(context.Background(), n)
	var nf *NotFound
	if !errors.As(err, &nf) || nf.DNSLive == nil || !*nf.DNSLive {
		t.Fatalf("Lookup err = %v, want NotFound with DNSLive=true", err)
	}

	// No answers and NXDOMAIN: provably not live.
	dead := NewRouter(furry, nil, nil, nil, nil, fakeQuerier{resp: &dnsq.Response{Rcode: "NXDOMAIN"}})
	_, err = dead.Lookup(context.Background(), n)
	if !errors.As(err, &nf) || nf.DNSLive == nil || *nf.DNSLive {
		t.Fatalf("Lookup err = %v, want NotFound with DNSLive=false", err)
	}

	// DNS error: unknown, not false.
	unknown := NewRouter(furry, nil, nil, nil, nil, fakeQuerier{err: errors.New("boom")})
	_, err = unknown.Lookup(context.Background(), n)
	if !errors.As(err, &nf) || nf.DNSLive != nil {
		t.Fatalf("Lookup err = %v, want NotFound with DNSLive=nil", err)
	}

	// A plain registry name passes through untouched.
	plain := NewRouter(furry, nil, nil, nil, nil, fakeQuerier{})
	n2, _ := domain.Parse("example.com")
	res, err := plain.Lookup(context.Background(), n2)
	if err != nil || res != nil {
		t.Errorf("Lookup(example.com) = %v, %v, want (nil, nil)", res, err)
	}
}
