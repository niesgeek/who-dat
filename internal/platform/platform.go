// Package platform queries platforms that run their own namespaces and publish
// a query API for them (FurryBox, SEUS, Yunamo). These names are not registry
// records, so RDAP/WHOIS must never answer for them; the platform's own API
// is the only authority. A platform that publishes no query API is not
// handled here — domain.PlatformNamespace refuses those names with a pointer
// to the platform.
package platform

import (
	"context"
	"errors"
	"time"

	"github.com/lissy93/who-dat/internal/dnsq"
	"github.com/lissy93/who-dat/internal/domain"
	"github.com/lissy93/who-dat/internal/model"
)

// NotFound means the platform answered and the name is not in its database.
// That is a real answer, not a failure: the caller must not fall through to
// the registry. DNSLive is tri-state: true when the name already answers in
// DNS (delegated elsewhere), false when it provably does not, nil when the
// DNS check was skipped or inconclusive.
type NotFound struct {
	Provider    string
	ProviderURL string
	Suffix      string
	Reason      string
	DNSLive     *bool
}

func (e *NotFound) Error() string {
	return "platform " + e.Provider + " has no record for suffix " + e.Suffix + " (" + e.Reason + ")"
}

// FurryBoxSuffix returns the FurryBox namespace a host sits in, if any. The
// parent domain itself is a normal registry record and does not match; only
// names under it do. The list lives in domain so Parse can find the same
// registrable boundary.
func FurryBoxSuffix(host string) (string, bool) {
	return domain.FurryBoxSuffixFor(host)
}

// Router dispatches a lookup to the platform that owns the name, if any.
// Lookup returns (nil, nil) when no platform owns the name and the caller
// should continue to RDAP/WHOIS.
type Router struct {
	Furry  *FurryClient
	Seus   *SeusClient
	Dir    *SeusDirectory
	Yunamo *YunamoClient
	YDir   *YunamoDirectory
	DNS    dnsq.Querier // nil disables the DNS-live check on platform misses
}

// NewRouter wires the platform clients. Any of them may be nil to disable
// that platform (its names then fall through to the registry path).
func NewRouter(furry *FurryClient, seus *SeusClient, dir *SeusDirectory, yunamo *YunamoClient, ydir *YunamoDirectory, dns dnsq.Querier) *Router {
	return &Router{Furry: furry, Seus: seus, Dir: dir, Yunamo: yunamo, YDir: ydir, DNS: dns}
}

// Lookup answers from the owning platform, or (nil, nil) to continue.
func (r *Router) Lookup(ctx context.Context, n domain.Name) (*model.Result, error) {
	if r == nil {
		return nil, nil
	}
	if suf, ok := FurryBoxSuffix(n.ASCII); ok && r.Furry != nil {
		res, err := r.Furry.Lookup(ctx, n, suf)
		return r.finish(ctx, res, err, n)
	}
	if r.Seus != nil && r.Dir != nil {
		if suf, ok := r.Dir.SuffixFor(ctx, n.ASCII); ok {
			res, err := r.Seus.Lookup(ctx, n, suf)
			return r.finish(ctx, res, err, n)
		}
	}
	if r.Yunamo != nil && r.YDir != nil {
		if suf, ok := r.YDir.SuffixFor(ctx, n.ASCII); ok {
			res, err := r.Yunamo.Lookup(ctx, n, suf)
			return r.finish(ctx, res, err, n)
		}
	}
	return nil, nil
}

func (r *Router) finish(ctx context.Context, res *model.Result, err error, n domain.Name) (*model.Result, error) {
	if err == nil {
		return res, nil
	}
	var nf *NotFound
	if ok := errors.As(err, &nf); ok && r.DNS != nil {
		nf.DNSLive = r.dnsLive(ctx, n.ASCII)
	}
	return nil, err
}

// dnsLive reports whether the name already answers NS queries in DNS, for the
// "platform says no, but is it live anyway" check. Nil means unknown.
func (r *Router) dnsLive(ctx context.Context, asciiDomain string) *bool {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	resp, err := r.DNS.Query(ctx, dnsq.Query{Name: asciiDomain, Type: "NS", Server: "8.8.8.8", RD: true})
	if err != nil || resp == nil {
		return nil
	}
	switch resp.Rcode {
	case "NOERROR":
		live := len(resp.Answer) > 0
		return &live
	case "NXDOMAIN":
		live := false
		return &live
	default:
		return nil
	}
}
