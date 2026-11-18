package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lissy93/who-dat/internal/domain"
	"github.com/lissy93/who-dat/internal/model"
	"github.com/lissy93/who-dat/internal/srcerr"
)

const (
	// seusWhoisURL is SEUS's public, keyless whois API: it answers the same
	// fields the platform's own whois page shows.
	seusWhoisURL = "https://s.eus/api/whois"
	// seusSuffixesURL is the public suffix directory for SEUS's BYOS program:
	// user-supplied domains (fs.kg, bg5.net, ...) that SEUS resells as
	// registrable suffixes. The list changes as domains join or leave, so it
	// is fetched live and cached briefly rather than hardcoded.
	seusSuffixesURL = "https://s.eus/api/domains/suffixes"

	seusName   = "SEUS"
	seusURL    = "https://s.eus/zh/domains/register"
	seusServer = "s.eus"
)

// SeusClient queries the SEUS public whois API.
type SeusClient struct {
	http     *http.Client
	endpoint string // overridable for tests; defaults to seusWhoisURL
}

// NewSeusClient returns a client.
func NewSeusClient(httpClient *http.Client) *SeusClient {
	return &SeusClient{http: httpClient, endpoint: seusWhoisURL}
}

type seusResponse struct {
	State  string      `json:"state"`
	FQDN   string      `json:"fqdn"`
	Fields []seusField `json:"fields"`
}

type seusField struct {
	K   string `json:"k"`
	V   string `json:"v"`
	Img string `json:"img"` // base64 anti-scrape image for emails; never rendered
}

// Lookup returns the SEUS record for a name under one of its BYOS suffixes,
// or *NotFound when the platform has no record for it.
func (c *SeusClient) Lookup(ctx context.Context, n domain.Name, suffix string) (*model.Result, error) {
	start := time.Now()
	u := c.endpoint + "?domain=" + url.QueryEscape(n.ASCII)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: seus lookup: %v", srcerr.ErrUpstream, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: seus read: %v", srcerr.ErrUpstream, err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &srcerr.RateLimited{Err: fmt.Errorf("seus rate limited")}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: seus status %d", srcerr.ErrUpstream, resp.StatusCode)
	}
	var res seusResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("%w: seus decode: %v", srcerr.ErrUpstream, err)
	}
	if res.State != "found" {
		return nil, &NotFound{Provider: seusName, ProviderURL: seusURL, Suffix: suffix, Reason: "NOT_REGISTERED"}
	}
	return mapSeus(n, suffix, &res, time.Since(start).Milliseconds(), len(raw)), nil
}

func mapSeus(n domain.Name, suffix string, res *seusResponse, durationMs int64, bytes int) *model.Result {
	r := model.New(n.ASCII, n.ASCII, n.TLD)
	r.IsRegistered = true
	r.Registrar.Name = model.Str("SEUS Community")
	r.Registrar.URL = model.Str("https://s.eus")
	r.Platform = &model.PlatformInfo{Name: seusName, URL: seusURL, Suffix: suffix}
	r.Meta = model.Meta{
		Source:     model.SourcePlatform,
		Server:     model.Str(seusServer),
		FetchedAt:  time.Now().UTC(),
		DurationMs: durationMs,
		Bytes:      bytes,
	}
	seenNS := map[string]bool{}
	for _, f := range res.Fields {
		v := strings.TrimSpace(f.V)
		switch f.K {
		case "Creation Date":
			r.Dates.Created = parseDatePtr(v)
		case "Updated Date":
			r.Dates.Updated = parseDatePtr(v)
		case "Registry Expiry Date":
			r.Dates.Expires = parseDatePtr(v)
		case "Domain Status":
			if v != "" {
				r.Status = []string{strings.ToLower(v)}
			}
		case "Nameserver":
			if v != "" && !seenNS[v] {
				seenNS[v] = true
				r.Nameservers = append(r.Nameservers, model.Nameserver{Name: v, IPv4: []string{}, IPv6: []string{}})
			}
		case "DNSSEC":
			r.DNSSEC.Signed = strings.Contains(strings.ToLower(v), "signed") && !strings.Contains(strings.ToLower(v), "unsigned")
		case "Registrant Name":
			setContactName(&r.Contacts.Registrant, v)
		case "Registrant Organization":
			setContactOrg(&r.Contacts.Registrant, v)
		case "Admin Name":
			setContactName(&r.Contacts.Admin, v)
		case "Admin Organization":
			setContactOrg(&r.Contacts.Admin, v)
		case "Tech Name":
			setContactName(&r.Contacts.Tech, v)
		case "Tech Organization":
			setContactOrg(&r.Contacts.Tech, v)
		}
	}
	if len(r.Status) == 0 {
		r.Status = []string{"ok"}
	}
	if r.Dates.Created != nil {
		r.Events = append(r.Events, model.Event{Action: "registration", Date: r.Dates.Created})
	}
	if r.Dates.Updated != nil {
		r.Events = append(r.Events, model.Event{Action: "last changed", Date: r.Dates.Updated})
	}
	if r.Dates.Expires != nil {
		r.Events = append(r.Events, model.Event{Action: "expiration", Date: r.Dates.Expires})
	}
	r.Raw = []byte(seusRawText(n.ASCII, res))
	r.RawContentType = "text/plain; charset=utf-8"
	return r
}

func setContactName(c *model.Contact, v string) {
	if v == "" || strings.EqualFold(v, "Not disclosed") {
		return
	}
	c.Name = model.Str(v)
	c.Redacted = false
}

func setContactOrg(c *model.Contact, v string) {
	if v == "" || strings.EqualFold(v, "Not disclosed") {
		return
	}
	c.Organization = model.Str(v)
	c.Redacted = false
}

func parseDatePtr(v string) *time.Time {
	if v == "" {
		return nil
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 UTC"} {
		if t, err := time.Parse(layout, strings.TrimSpace(v)); err == nil {
			return model.Time(t)
		}
	}
	return nil
}

// seusRawText renders the platform record as whois-style text, the same shape
// domain.fs.kg shows for its raw card. Email fields are served by SEUS as
// base64 images to resist scraping; they render as "Not disclosed".
func seusRawText(domain string, res *seusResponse) string {
	var b strings.Builder
	b.WriteString("% SEUS platform record (via the s.eus public whois API, not registry whois)\n")
	b.WriteString("% This suffix is a user-supplied domain SEUS resells; the registry does not record this layer.\n")
	for _, f := range res.Fields {
		v := strings.TrimSpace(f.V)
		if v == "" {
			if f.Img != "" {
				b.WriteString(f.K + ":Not disclosed\n")
			}
			continue
		}
		b.WriteString(f.K + ":" + v + "\n")
	}
	return b.String()
}

// SeusDirectory is the live list of SEUS BYOS suffixes, fetched from the
// public directory endpoint and cached briefly. The list changes as domains
// join or leave, so it is never hardcoded; on a fetch failure the last known
// list is kept, and an empty list means "no directory" rather than a guess.
type SeusDirectory struct {
	http     *http.Client
	endpoint string // overridable for tests; defaults to seusSuffixesURL

	mu        sync.Mutex
	suffixes  []string
	fetchedAt time.Time
}

// NewSeusDirectory returns a directory backed by httpClient.
func NewSeusDirectory(httpClient *http.Client) *SeusDirectory {
	return &SeusDirectory{http: httpClient, endpoint: seusSuffixesURL}
}

const seusDirectoryTTL = time.Hour

type seusSuffixesResponse struct {
	Suffixes []struct {
		Suffix  string `json:"suffix"`
		Enabled *bool  `json:"enabled"`
	} `json:"suffixes"`
}

// Suffixes returns the current BYOS suffix list, refreshing it when stale.
func (d *SeusDirectory) Suffixes(ctx context.Context) []string {
	d.mu.Lock()
	fresh := d.suffixes != nil && time.Since(d.fetchedAt) < seusDirectoryTTL
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

func (d *SeusDirectory) fetch(ctx context.Context) ([]string, error) {
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
		return nil, fmt.Errorf("seus directory status %d", resp.StatusCode)
	}
	var res seusSuffixesResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&res); err != nil {
		return nil, err
	}
	out := []string{}
	for _, s := range res.Suffixes {
		suf := strings.ToLower(strings.TrimSpace(s.Suffix))
		if suf == "" || strings.Index(suf, ".") <= 0 {
			continue
		}
		if s.Enabled != nil && !*s.Enabled {
			continue
		}
		out = append(out, suf)
	}
	return out, nil
}

// SuffixFor returns the SEUS BYOS suffix a host sits in, if any, matching on
// the longest suffix. The parent domain itself is not a SEUS name.
func (d *SeusDirectory) SuffixFor(ctx context.Context, host string) (string, bool) {
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
