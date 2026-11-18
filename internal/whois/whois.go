// Package whois is the port-43 WHOIS fallback for TLDs without an RDAP server. It wraps
// the blocking likexian client with context handling and maps the parsed result onto the
// canonical model.
package whois

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	gowhois "github.com/likexian/whois"

	"github.com/lissy93/who-dat/internal/domain"
	"github.com/lissy93/who-dat/internal/model"
	"github.com/lissy93/who-dat/internal/srcerr"
)

// Client performs WHOIS lookups.
type Client struct{}

// NewClient returns a WHOIS client.
func NewClient() *Client { return &Client{} }

// Lookup queries WHOIS for n, honoring ctx cancellation/deadline
func (c *Client) Lookup(ctx context.Context, n domain.Name) (*model.Result, error) {
	start := time.Now()
	r, err := c.query(ctx, n)
	if err != nil {
		return nil, &srcerr.SourceError{Source: model.SourceWhois, Err: err}
	}
	r.Meta.DurationMs = time.Since(start).Milliseconds()
	return r, nil
}

// query runs the blocking WHOIS lookup. The lib picks the server itself, so we never
// learn which host we actually asked — except for suffix overrides below, where the
// server is fixed and recorded on the result.
func (c *Client) query(ctx context.Context, n domain.Name) (*model.Result, error) {
	type result struct {
		raw string
		err error
	}
	ch := make(chan result, 1)

	go func() {
		wc := gowhois.NewClient()
		if dl, ok := ctx.Deadline(); ok {
			wc.SetTimeout(time.Until(dl))
		}
		raw, err := wc.Whois(n.ASCII, whoisServersFor(n.ASCII)...)
		ch <- result{raw: raw, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %v", srcerr.ErrTimeout, ctx.Err())
	case res := <-ch:
		if res.err != nil {
			// timeout
			if ctx.Err() != nil {
				return nil, fmt.Errorf("%w: %v", srcerr.ErrTimeout, res.err)
			}
			if errors.Is(res.err, gowhois.ErrWhoisServerNotFound) {
				return nil, fmt.Errorf("%w: %v", srcerr.ErrNoSource, res.err)
			}
			// referral failed (maybe URL instead of host), fallback to usable record if present
			if res.raw == "" {
				return nil, fmt.Errorf("%w: whois query: %v", srcerr.ErrUpstream, res.err)
			}
		}
		r, err := mapWhois(n, res.raw)
		if err != nil {
			return nil, err
		}
		if servers := whoisServersFor(n.ASCII); len(servers) > 0 && r.Meta.Server == nil {
			r.Meta.Server = model.Str(servers[0])
		}
		return r, nil
	}
}

// whoisServersFor returns explicit port-43 servers for suffixes whose host does
// not follow the TLD. pp.ua names live on whois.pp.ua, while the .ua whois
// server only serves the TLD itself (its RDAP answers 501 for third-level
// names). Empty means "let the library pick from its own table".
func whoisServersFor(asciiDomain string) []string {
	if strings.HasSuffix(asciiDomain, ".pp.ua") && len(asciiDomain) > len(".pp.ua") {
		return []string{"whois.pp.ua"}
	}
	return nil
}
