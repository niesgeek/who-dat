package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lissy93/who-dat/internal/config"
	"github.com/lissy93/who-dat/internal/dnsq"
)

type stubDNS struct {
	resp *dnsq.Response
	err  error
	last dnsq.Query
}

func (s *stubDNS) Query(_ context.Context, q dnsq.Query) (*dnsq.Response, error) {
	s.last = q
	if s.err != nil {
		return nil, s.err
	}
	if s.resp != nil {
		return s.resp, nil
	}
	return &dnsq.Response{
		OK: true, Server: q.Server, Name: "example.com", Type: q.Type, Rcode: "NOERROR",
		Transport: "udp", ElapsedMS: 4,
		Flags: dnsq.Flags{RD: q.RD, AD: true},
		Answer: []dnsq.RR{{
			Name: "example.com.", Type: "A", TTL: 300, Data: "192.0.2.10",
		}},
		Authority: []dnsq.RR{}, Additional: []dnsq.RR{}, DNSSEC: q.DNSSEC,
	}, nil
}

func dnsHandler(stub *stubDNS) http.Handler {
	cfg := &config.Config{LookupTimeout: 2 * time.Second, MaxDomains: 5, DNSServer: "8.8.8.8", DNSTimeout: 4 * time.Second}
	s := newServer(cfg, nil)
	s.dns = stub
	return s.routes()
}

func TestDNSAPITextForCurlJSONForBrowser(t *testing.T) {
	h := dnsHandler(&stubDNS{})

	curl := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dns?name=example.com&type=A&server=8.8.8.8", nil)
	req.Header.Set("User-Agent", "curl/8.5.0")
	h.ServeHTTP(curl, req)
	if curl.Code != http.StatusOK || !strings.Contains(curl.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("curl status/type = %d %s", curl.Code, curl.Header().Get("Content-Type"))
	}
	if !strings.Contains(curl.Body.String(), "rcode=NOERROR") || !strings.Contains(curl.Body.String(), "192.0.2.10") {
		t.Fatalf("curl body = %s", curl.Body)
	}
	if curl.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache = %q", curl.Header().Get("Cache-Control"))
	}

	browser := httptest.NewRecorder()
	breq := httptest.NewRequest(http.MethodGet, "/api/dns?name=example.com&type=A", nil)
	breq.Header.Set("User-Agent", "Mozilla/5.0")
	breq.Header.Set("Accept", "application/json")
	h.ServeHTTP(browser, breq)
	if !strings.Contains(browser.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("browser type = %s", browser.Header().Get("Content-Type"))
	}
	var body dnsq.Response
	if err := json.Unmarshal(browser.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK || body.Answer[0].Data != "192.0.2.10" || !body.DNSSEC {
		t.Fatalf("json = %+v", body)
	}

	forced := httptest.NewRecorder()
	freq := httptest.NewRequest(http.MethodGet, "/api/dns?name=example.com&format=json", nil)
	freq.Header.Set("User-Agent", "curl/8.5.0")
	h.ServeHTTP(forced, freq)
	if !strings.Contains(forced.Header().Get("Content-Type"), "json") {
		t.Fatal("format=json did not override curl")
	}
}

func TestDNSAPIRejectsPrivateAndBadName(t *testing.T) {
	h := dnsHandler(&stubDNS{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/dns?name=example.com&server=127.0.0.1", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "PRIVATE_SERVER") {
		t.Fatalf("private = %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/dns?name=", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "INVALID_NAME") {
		t.Fatalf("name = %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dns?name=_dmarc.example.com&type=TXT&dnssec=0&rd=0&timeout=250", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("underscore = %d %s", rec.Code, rec.Body)
	}
}

func TestDNSPageAndLabAndWhoami(t *testing.T) {
	h := dnsHandler(&stubDNS{})
	page := httptest.NewRecorder()
	h.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/dns", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("dns page = %d %s", page.Code, page.Header().Get("Content-Type"))
	}
	body := page.Body.String()
	for _, want := range []string{"/api/dns", "example.com", "WHOIS", "/contact", "not a validated signature"} {
		if !strings.Contains(body, want) {
			t.Errorf("dns page missing %q", want)
		}
	}

	home := httptest.NewRecorder()
	h.ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(home.Body.String(), `href="/dns"`) {
		t.Fatal("home missing DNS link")
	}

	lab := httptest.NewRecorder()
	h.ServeHTTP(lab, httptest.NewRequest(http.MethodGet, "/api/dns/lab?name=example.com&type=A", nil))
	if lab.Code != http.StatusOK {
		t.Fatalf("lab = %d %s", lab.Code, lab.Body)
	}
	var report dnsq.Report
	if err := json.Unmarshal(lab.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.OK || report.DNSSEC.CryptoValidation || !strings.Contains(report.Disclaimer, "not a validated signature") {
		t.Fatalf("lab report = %+v", report.DNSSEC)
	}

	who := httptest.NewRecorder()
	wreq := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	wreq.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	wreq.Header.Set("X-Vercel-IP-Country", "US")
	wreq.Header.Set("X-Vercel-IP-City", "New%20York")
	wreq.Header.Set("X-Vercel-Id", "iad1::sfo1")
	wreq.RemoteAddr = "10.1.1.1:4000"
	h.ServeHTTP(who, wreq)
	var me map[string]any
	if err := json.Unmarshal(who.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me["ip"] != "203.0.113.9" || me["country"] != "US" || me["city"] != "New York" || me["pop"] != "iad1" || me["thirdPartyGeo"] != false || me["source"] != "connection" {
		t.Fatalf("whoami = %+v", me)
	}
	if who.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("whoami cached")
	}
}

func TestWhoisStillLooksup(t *testing.T) {
	h := newTestServer(registered(), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/whois/example.com", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"example.com"`) {
		t.Fatalf("whois = %d %s", rec.Code, rec.Body)
	}
}
