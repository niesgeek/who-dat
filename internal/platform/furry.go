package platform

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lissy93/who-dat/internal/domain"
	"github.com/lissy93/who-dat/internal/model"
	"github.com/lissy93/who-dat/internal/srcerr"
)

// FurryBox publishes its whois as plain text at https://whois.furry.box/<domain>
// — the same endpoint its own whois page prints as the command-line form
// ("curl whois.furry.box/<domain>"). No key, no POST, just a GET that returns
// whois-style text. (The platform also runs a Supabase edge function behind
// its web form, but the text endpoint is the public, keyless interface and
// the one verified reachable here.)
const (
	furryBaseURL = "https://whois.furry.box/"

	furryName   = "FurryBox"
	furryURL    = "https://www.furry.box/whois/"
	furryServer = "whois.furry.box"
)

// FurryClient queries the FurryBox whois text endpoint.
type FurryClient struct {
	http     *http.Client
	endpoint string // base URL, overridable for tests; defaults to furryBaseURL
}

// NewFurryClient returns a client.
func NewFurryClient(httpClient *http.Client) *FurryClient {
	return &FurryClient{http: httpClient, endpoint: furryBaseURL}
}

// Lookup returns the platform record for a FurryBox name, or *NotFound when
// the platform says the name is not registered there.
func (c *FurryClient) Lookup(ctx context.Context, n domain.Name, suffix string) (*model.Result, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+n.ASCII, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: furrybox lookup: %v", srcerr.ErrUpstream, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: furrybox read: %v", srcerr.ErrUpstream, err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &srcerr.RateLimited{Err: fmt.Errorf("furrybox rate limited")}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: furrybox status %d", srcerr.ErrUpstream, resp.StatusCode)
	}
	text := string(raw)
	switch {
	case strings.Contains(text, "Domain not registered."):
		return nil, &NotFound{Provider: furryName, ProviderURL: furryURL, Suffix: suffix, Reason: "NOT_REGISTERED"}
	case strings.Contains(text, "Input is not a valid domain name."):
		return nil, &NotFound{Provider: furryName, ProviderURL: furryURL, Suffix: suffix, Reason: "INVALID"}
	case strings.Contains(text, "Domain not found."):
		return nil, &NotFound{Provider: furryName, ProviderURL: furryURL, Suffix: suffix, Reason: "NOT_OURS"}
	}
	fields := parseFurryText(text)
	if len(fields["Domain Name"]) == 0 || fields["Domain Name"][0] == "" {
		return nil, fmt.Errorf("%w: furrybox unexpected response", srcerr.ErrUpstream)
	}
	return mapFurry(n, suffix, fields, text, time.Since(start).Milliseconds(), len(raw)), nil
}

// parseFurryText reads the whois-style text into key/value fields. Name
// Servers continue on indented lines without a colon; the "(FurryBox
// default)" note is not a nameserver.
func parseFurryText(text string) map[string][]string {
	fields := map[string][]string{}
	var current string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "%") || strings.TrimSpace(line) == "" {
			continue
		}
		if i := strings.Index(line, ":"); i > 0 && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			key := strings.TrimSpace(line[:i])
			val := strings.TrimSpace(line[i+1:])
			fields[key] = append(fields[key], val)
			current = key
			continue
		}
		if current == "Name Servers" {
			if v := strings.TrimSpace(line); v != "" && !strings.HasPrefix(v, "(") {
				fields[current] = append(fields[current], v)
			}
		}
	}
	return fields
}

func mapFurry(n domain.Name, suffix string, fields map[string][]string, rawText string, durationMs int64, bytes int) *model.Result {
	first := func(key string) string {
		if vs := fields[key]; len(vs) > 0 {
			return vs[0]
		}
		return ""
	}
	r := model.New(n.ASCII, n.ASCII, n.TLD)
	r.IsRegistered = true
	r.Registrar.Name = model.Str(furryName)
	r.Registrar.URL = model.Str(furryURL)
	r.Platform = &model.PlatformInfo{Name: furryName, URL: furryURL, Suffix: suffix}
	r.Meta = model.Meta{
		Source:     model.SourcePlatform,
		Server:     model.Str(furryServer),
		FetchedAt:  time.Now().UTC(),
		DurationMs: durationMs,
		Bytes:      bytes,
	}
	if state := strings.ToLower(strings.TrimSpace(first("Status"))); state != "" {
		r.Status = []string{state}
	} else {
		r.Status = []string{"active"}
	}
	r.Dates.Created = parseTimePtr(ptr(first("Created")))
	expires := first("Expires")
	if strings.HasPrefix(strings.ToLower(expires), "never") {
		r.Permanent = true
	} else {
		r.Dates.Expires = parseTimePtr(ptr(expires))
	}
	if r.Dates.Created != nil {
		r.Events = append(r.Events, model.Event{Action: "registration", Date: r.Dates.Created})
	}
	if r.Dates.Expires != nil {
		r.Events = append(r.Events, model.Event{Action: "expiration", Date: r.Dates.Expires})
	}
	if email := first("Registrant"); email != "" {
		// The platform masks the address itself (e.g. f****m@hotmail.com);
		// what it chose to show is safe to repeat.
		r.Contacts.Registrant.Email = model.Str(email)
		r.Contacts.Registrant.Redacted = false
	}
	for _, ns := range fields["Name Servers"] {
		if ns = strings.TrimSpace(ns); ns != "" {
			r.Nameservers = append(r.Nameservers, model.Nameserver{Name: ns, IPv4: []string{}, IPv6: []string{}})
		}
	}
	// The raw card shows the platform's own text verbatim.
	r.Raw = []byte(rawText)
	r.RawContentType = "text/plain; charset=utf-8"
	return r
}

func ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func parseTimePtr(s *string) *time.Time {
	if s == nil || strings.TrimSpace(*s) == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02", "2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 UTC"} {
		if t, err := time.Parse(layout, strings.TrimSpace(*s)); err == nil {
			return model.Time(t)
		}
	}
	return nil
}
