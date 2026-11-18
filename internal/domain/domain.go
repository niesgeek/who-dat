// Package domain sanitizes user input into a registrable domain name. It accepts loose
// input (full URLs, mixed case, IDNs, trailing dots) and returns the registrable domain
// (eTLD+1) that RDAP and WHOIS actually operate on.
package domain

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// ErrInvalidDomain means the input could not be parsed into a hostname.
var ErrInvalidDomain = errors.New("could not parse a registrable domain")

// ErrNoPublicSuffix means the host has no valid public suffix (so no registrable domain).
var ErrNoPublicSuffix = errors.New("no valid public suffix")

// PlatformNamespace is a namespace a platform carved out of its own registered
// parent domain (e.g. DNSHE selling names under cc.cd). The registry only ever
// records the parent, so a lookup for a name inside one must never be reported
// as "unregistered": the record lives with the platform, not the registry.
type PlatformNamespace struct {
	// Suffix is the platform namespace, e.g. "cc.cd".
	Suffix string
	// Name is the platform operator, e.g. "DNSHE".
	Name string
	// URL is the platform's own site or whois page.
	URL string
	// Parent is the registrable parent domain the registry does record.
	Parent string
	// HasLookup reports whether the platform publishes its own query page/API
	// for names in this namespace.
	HasLookup bool
}

// platformNamespaces maps platform-run suffixes with no public query
// interface to their operator. Names under these suffixes are refused by
// Parse with a PlatformNamespaceError: the record lives with the platform,
// not the registry, and there is no API to ask. Platforms that do publish a
// query API (FurryBox, SEUS, Yunamo) are not listed here — they are queried
// by the platform package instead of being refused.
var platformNamespaces = map[string]PlatformNamespace{
	"cc.cd":   {Suffix: "cc.cd", Name: "DNSHE", URL: "https://www.dnshe.com/", Parent: "cc.cd", HasLookup: false},
	"bot.cd":  {Suffix: "bot.cd", Name: "DNSHE", URL: "https://www.dnshe.com/", Parent: "bot.cd", HasLookup: false},
	"us.ci":   {Suffix: "us.ci", Name: "DNSHE", URL: "https://www.dnshe.com/", Parent: "us.ci", HasLookup: false},
	"de5.net": {Suffix: "de5.net", Name: "DNSHE", URL: "https://www.dnshe.com/", Parent: "de5.net", HasLookup: false},
}

// furryBoxSuffixes are the namespaces FurryBox carved out of its own domains.
// Names under them are platform records queried through the FurryBox API, not
// registry records. The platform package owns the query; this list only tells
// Parse where the registrable boundary sits (the PSL would collapse
// "myname.owo.name" to "owo.name" and lose the label).
var furryBoxSuffixes = map[string]bool{
	"paw.fm": true, "end.ac": true, "qwq.name": true, "owo.name": true,
	"site.tv": true, "xwx.me": true, "furry.box": true,
}

// FurryBoxSuffixFor returns the FurryBox namespace a host sits in, if any. The
// parent domain itself is a normal registry record and does not match; only
// names under it do.
func FurryBoxSuffixFor(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	labels := strings.Split(host, ".")
	for i := 1; i < len(labels); i++ {
		if suf := strings.Join(labels[i:], "."); furryBoxSuffixes[suf] {
			return suf, true
		}
	}
	return "", false
}

// seusSuffixSnapshot is the SEUS BYOS directory as last seen (live list at
// https://s.eus/api/domains/suffixes). The platform package fetches that list
// live for routing; this snapshot only tells Parse where the registrable
// boundary sits, so a SEUS name keeps its label instead of collapsing to the
// parent in the PSL. Refresh it when the directory changes: a suffix missing
// here parses as its parent and never reaches the platform lookup, while a
// suffix that left SEUS still parses as a platform name and falls through to
// RDAP for the parent TLD.
var seusSuffixSnapshot = map[string]bool{
	"fs.kg": true, "is-a.si": true, "us.mw": true, "bg5.net": true, "nastu.net": true,
}

// yunamoSuffixSnapshot is the Yunamo root-domain directory as last seen
// (live list at https://yunamo.com/api/public/root-domains). The platform
// package fetches that list live for routing; this snapshot only tells Parse
// where the registrable boundary sits, so a Yunamo name keeps its label
// instead of collapsing to the parent in the PSL. Refresh it when the
// directory changes: a suffix missing here parses as its parent and never
// reaches the platform lookup, while a suffix that left Yunamo still parses
// as a platform name and falls through to RDAP for the parent TLD.
var yunamoSuffixSnapshot = map[string]bool{
	"loc.cc": true, "vvpp.cc": true,
}

// queryablePlatformSuffixFor returns the platform namespace a host sits in
// when that platform publishes a query API (FurryBox, SEUS and Yunamo
// snapshots). The parent domain itself does not match; only names under it
// do.
func queryablePlatformSuffixFor(host string) (string, bool) {
	if suf, ok := FurryBoxSuffixFor(host); ok {
		return suf, true
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	labels := strings.Split(host, ".")
	for i := 1; i < len(labels); i++ {
		if suf := strings.Join(labels[i:], "."); seusSuffixSnapshot[suf] || yunamoSuffixSnapshot[suf] {
			return suf, true
		}
	}
	return "", false
}

type PlatformNamespaceError struct {
	Namespace PlatformNamespace
	Host      string
}

func (e *PlatformNamespaceError) Error() string {
	return "platform-run namespace " + e.Namespace.Suffix + " (" + e.Namespace.Name + "), not a registry record"
}

// PlatformNamespaceFor returns the platform namespace a host sits in, if any,
// matching on the longest suffix. The parent domain itself (e.g. "cc.cd") is
// a normal registry record and does not match; only names under it do.
func PlatformNamespaceFor(host string) (PlatformNamespace, bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	labels := strings.Split(host, ".")
	for i := 1; i < len(labels); i++ {
		if ns, ok := platformNamespaces[strings.Join(labels[i:], ".")]; ok {
			return ns, true
		}
	}
	return PlatformNamespace{}, false
}

// Name is a parsed, registrable domain.
type Name struct {
	ASCII   string // punycode/ASCII form, used for lookups, e.g. "xn--n3h.com"
	Unicode string // human form, e.g. "☃.com"; equals ASCII when not an IDN
	TLD     string // the public suffix, e.g. "com" or "co.uk"
}

// IsIDN reports whether the name contained non-ASCII labels.
func (n Name) IsIDN() bool { return n.Unicode != n.ASCII }

// Parse extracts the registrable domain from raw input.
func Parse(raw string) (Name, error) {
	host := hostname(raw)
	if host == "" {
		return Name{}, ErrInvalidDomain
	}

	// A name inside a platform-run namespace is not a registry record at all:
	// refuse it here so no caller can mistake it for an unregistered domain.
	if ns, ok := PlatformNamespaceFor(host); ok {
		return Name{}, &PlatformNamespaceError{Namespace: ns, Host: host}
	}

	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return Name{}, ErrInvalidDomain
	}

	// A name under a queryable platform suffix is a platform record, not a
	// registry record: the registrable boundary is the label immediately
	// before the platform suffix, and the suffix itself is the TLD. Without
	// this the PSL would collapse "myname.owo.name" to "owo.name" and the
	// queried name would be wrong.
	if suffix, ok := queryablePlatformSuffixFor(ascii); ok {
		labels := strings.Split(ascii, ".")
		sufLabels := strings.Split(suffix, ".")
		registrable := labels[len(labels)-len(sufLabels)-1] + "." + suffix
		unicode, err := idna.Lookup.ToUnicode(registrable)
		if err != nil {
			unicode = registrable
		}
		return Name{ASCII: registrable, Unicode: unicode, TLD: suffix}, nil
	}

	registrable, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		return Name{}, ErrNoPublicSuffix
	}
	suffix, _ := publicsuffix.PublicSuffix(registrable)

	unicode, err := idna.Lookup.ToUnicode(registrable)
	if err != nil {
		unicode = registrable
	}

	return Name{ASCII: registrable, Unicode: unicode, TLD: suffix}, nil
}

// hostname strips scheme, credentials, port, path, query, and a trailing dot, leaving a
// bare lowercase host.
func hostname(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}
