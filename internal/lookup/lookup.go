// Package lookup orchestrates a domain lookup: cache, then RDAP, then WHOIS fallback.
package lookup

import (
	"context"
	"errors"
	"fmt"

	"github.com/lissy93/who-dat/internal/cache"
	"github.com/lissy93/who-dat/internal/domain"
	"github.com/lissy93/who-dat/internal/model"
	"github.com/lissy93/who-dat/internal/platform"
	"github.com/lissy93/who-dat/internal/srcerr"
)

// Source is a single lookup backend. The interface lives here, at the consumer, and is
// satisfied by *rdap.Client and *whois.Client.
type Source interface {
	Lookup(ctx context.Context, n domain.Name) (*model.Result, error)
}

// Service resolves a domain via platform APIs first (FurryBox, SEUS), then
// RDAP, falling back to WHOIS when no RDAP server exists for the TLD. Results
// are cached when a cache is configured.
type Service struct {
	rdap     Source
	whois    Source
	platform *platform.Router // nil disables platform lookups
	cache    *cache.Cache     // nil when caching is disabled
}

// NewService wires the RDAP and WHOIS sources, an optional platform router,
// and an optional cache.
func NewService(rdap, whois Source, c *cache.Cache, plat *platform.Router) *Service {
	return &Service{rdap: rdap, whois: whois, cache: c, platform: plat}
}

// Lookup returns the normalized result for n. A "not registered" answer is a success, not
// an error. On a cache hit the returned result has Meta.Cached set.
func (s *Service) Lookup(ctx context.Context, n domain.Name) (*model.Result, error) {
	if s.cache != nil {
		if cached, ok := s.cache.Get(n.ASCII); ok {
			hit := *cached
			hit.Meta.Cached = true
			return &hit, nil
		}
	}

	// Platform-owned names never reach the registry: FurryBox and SEUS run
	// their own namespaces and answer from their own APIs. A platform miss
	// is a final answer (the name is not registered there), not a cue to ask
	// the registry, which holds no record for these names at all.
	if s.platform != nil {
		if r, err := s.platform.Lookup(ctx, n); err != nil || r != nil {
			if err != nil {
				return nil, err
			}
			if s.cache != nil {
				s.cache.Set(n.ASCII, r)
			}
			return r, nil
		}
	}

	r, err := s.rdap.Lookup(ctx, n)
	if errors.Is(err, srcerr.ErrNoSource) {
		if r, err = s.whois.Lookup(ctx, n); err != nil {
			err = fmt.Errorf("no rdap server registered for .%s; fell back to %w", n.TLD, err)
		}
	}
	if err != nil {
		return nil, err
	}

	if s.cache != nil {
		s.cache.Set(n.ASCII, r)
	}
	return r, nil
}
