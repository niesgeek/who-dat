package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lissy93/who-dat/internal/domain"
	"github.com/lissy93/who-dat/internal/model"
	"github.com/lissy93/who-dat/internal/srcerr"
)

const (
	// yunamoWhoisURL is Yunamo's public, keyless whois API, documented under
	// "Public Endpoints (No Authentication)" at
	// https://yunamo.com/pages/api-reference. No key, no login, plain GET.
	yunamoWhoisURL = "https://yunamo.com/api/public/whois/"
	// yunamoRootDomainsURL is the public directory of Yunamo's root domains
	// (loc.cc, vvpp.cc, ...). The list changes as suffixes launch, so it is
	// fetched live and cached briefly rather than hardcoded.
	yunamoRootDomainsURL = "https://yunamo.com/api/public/root-domains"

	yunamoName   = "Yunamo"
	yunamoURL    = "https://yunamo.com/"
	yunamoServer = "yunamo.com"
)

// YunamoClient queries Yunamo's public whois API.
type YunamoClient struct {
	http     *http.Client
	endpoint string // overridable for tests; defaults to yunamoWhoisURL
}

// NewYunamoClient returns a client.
func NewYunamoClient(httpClient *http.Client) *YunamoClient {
	return &YunamoClient{http: httpClient, endpoint: yunamoWhoisURL}
}

type yunamoResponse struct {
	FullDomain  string   `json:"full_domain"`
	Registered  string   `json:"registered_at"`
	Expires     string   `json:"expires_at"`
	Status      string   `json:"status"`
	Nameservers []string `json:"nameservers"`
	// Scan is the platform's health check for the name (dns/http/ssl,
	// uptime, safe-browsing). It is not mapped to model fields; it rides in
	// the verbatim raw payload.
	Scan json.RawMessage `json:"scan"`
}

// Lookup returns the Yunamo record for a name under one of its suffixes, or
// *NotFound when the platform has no record for it (HTTP 404 with
// {"error":"Domain not found"}).
func (c *YunamoClient) Lookup(ctx context.Context, n domain.Name, suffix string) (*model.Result, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+n.ASCII, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: yunamo lookup: %v", srcerr.ErrUpstream, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: yunamo read: %v", srcerr.ErrUpstream, err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &srcerr.RateLimited{Err: fmt.Errorf("yunamo rate limited")}
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, &NotFound{Provider: yunamoName, ProviderURL: yunamoURL, Suffix: suffix, Reason: "NOT_REGISTERED"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: yunamo status %d", srcerr.ErrUpstream, resp.StatusCode)
	}
	var res yunamoResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: yunamo decode: %v", srcerr.ErrUpstream, err)
	}
	return mapYunamo(n, suffix, &res, raw, time.Since(start).Milliseconds()), nil
}

func mapYunamo(n domain.Name, suffix string, res *yunamoResponse, raw []byte, durationMs int64) *model.Result {
	r := model.New(n.ASCII, n.ASCII, n.TLD)
	r.IsRegistered = true
	r.Registrar.Name = model.Str(yunamoName)
	r.Registrar.URL = model.Str(yunamoURL)
	r.Platform = &model.PlatformInfo{Name: yunamoName, URL: yunamoURL, Suffix: suffix}
	r.Meta = model.Meta{
		Source:     model.SourcePlatform,
		Server:     model.Str(yunamoServer),
		FetchedAt:  time.Now().UTC(),
		DurationMs: durationMs,
		Bytes:      len(raw),
	}
	if res.Status != "" {
		r.Status = []string{strings.ToLower(res.Status)}
	} else {
		r.Status = []string{"ok"}
	}
	r.Dates.Created = parseDatePtr(res.Registered)
	r.Dates.Expires = parseDatePtr(res.Expires)
	seenNS := map[string]bool{}
	for _, ns := range res.Nameservers {
		ns = strings.ToLower(strings.TrimSpace(ns))
		if ns == "" || seenNS[ns] {
			continue
		}
		seenNS[ns] = true
		r.Nameservers = append(r.Nameservers, model.Nameserver{Name: ns, IPv4: []string{}, IPv6: []string{}})
	}
	if r.Dates.Created != nil {
		r.Events = append(r.Events, model.Event{Action: "registration", Date: r.Dates.Created})
	}
	if r.Dates.Expires != nil {
		r.Events = append(r.Events, model.Event{Action: "expiration", Date: r.Dates.Expires})
	}
	// The raw card shows the platform's reply verbatim, scan block included.
	r.Raw = raw
	r.RawContentType = "application/json"
	return r
}

// YunamoDirectory is the live list of Yunamo root domains, fetched from the
// public directory endpoint and cached briefly. On a fetch failure the last
// known list is kept, and an empty list means "no directory" rather than a
// guess.
type YunamoDirectory struct {
	http     *http.Client
	endpoint string // overridable for tests; defaults to yunamoRootDomainsURL

	mu        sync.Mutex
	suffixes  []string
	fetchedAt time.Time
}

// NewYunamoDirectory returns a directory backed by httpClient.
func NewYunamoDirectory(httpClient *http.Client) *YunamoDirectory {
	return &YunamoDirectory{http: httpClient, endpoint: yunamoRootDomainsURL}
}

const yunamoDirectoryTTL = time.Hour

type yunamoRootDomainsResponse struct {
	RootDomains []struct {
		Domain   string `json:"domain"`
		IsActive bool   `json:"is_active"`
	} `json:"root_domains"`
}

// Suffixes returns the current root-domain list, refreshing it when stale.
func (d *YunamoDirectory) Suffixes(ctx context.Context) []string {
	d.mu.Lock()
	fresh := d.suffixes != nil && time.Since(d.fetchedAt) < yunamoDirectoryTTL
	cached := d.suffixes
	d.mu.Unlock()
	if fresh {
		return cached
	}
	list, err := d.fetch(ctx)
	if err != nil {
		return cached // stale beats nothing; empty means "no directory"
	}
	d.mu.Lock()
	d.suffixes = list
	d.fetchedAt = time.Now()
	d.mu.Unlock()
	return list
}

func (d *YunamoDirectory) fetch(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("yunamo directory status %d", resp.StatusCode)
	}
	var res yunamoRootDomainsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&res); err != nil {
		return nil, err
	}
	out := []string{}
	for _, s := range res.RootDomains {
		suf := strings.ToLower(strings.TrimSpace(s.Domain))
		if suf == "" || strings.Index(suf, ".") <= 0 || !s.IsActive {
			continue
		}
		out = append(out, suf)
	}
	return out, nil
}

// SuffixFor returns the Yunamo root domain a host sits in, if any, matching
// on the longest suffix. The parent domain itself is not a Yunamo name.
func (d *YunamoDirectory) SuffixFor(ctx context.Context, host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	labels := strings.Split(host, ".")
	list := d.Suffixes(ctx)
	if len(list) == 0 {
		return "", false
	}
	set := make(map[string]bool, len(list))
	for _, s := range list {
		set[s] = true
	}
	for i := 1; i < len(labels); i++ {
		if suf := strings.Join(labels[i:], "."); set[suf] {
			return suf, true
		}
	}
	return "", false
}
