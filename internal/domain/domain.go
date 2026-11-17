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

// platformNamespaces maps platform-run suffixes to their operator. The DNSHE
// entries have no public query interface; the FurryBox/Yunamo entries do.
var platformNamespaces = map[string]PlatformNamespace{
	"cc.cd":     {Suffix: "cc.cd", Name: "DNSHE", URL: "https://www.dnshe.com/", Parent: "cc.cd", HasLookup: false},
	"bot.cd":    {Suffix: "bot.cd", Name: "DNSHE", URL: "https://www.dnshe.com/", Parent: "bot.cd", HasLookup: false},
	"us.ci":     {Suffix: "us.ci", Name: "DNSHE", URL: "https://www.dnshe.com/", Parent: "us.ci", HasLookup: false},
	"de5.net":   {Suffix: "de5.net", Name: "DNSHE", URL: "https://www.dnshe.com/", Parent: "de5.net", HasLookup: false},
	"loc.cc":    {Suffix: "loc.cc", Name: "Yunamo", URL: "https://yunamo.com/", Parent: "loc.cc", HasLookup: true},
	"paw.fm":    {Suffix: "paw.fm", Name: "FurryBox", URL: "https://www.furry.box/whois/", Parent: "paw.fm", HasLookup: true},
	"end.ac":    {Suffix: "end.ac", Name: "FurryBox", URL: "https://www.furry.box/whois/", Parent: "end.ac", HasLookup: true},
	"qwq.name":  {Suffix: "qwq.name", Name: "FurryBox", URL: "https://www.furry.box/whois/", Parent: "qwq.name", HasLookup: true},
	"owo.name":  {Suffix: "owo.name", Name: "FurryBox", URL: "https://www.furry.box/whois/", Parent: "owo.name", HasLookup: true},
	"site.tv":   {Suffix: "site.tv", Name: "FurryBox", URL: "https://www.furry.box/whois/", Parent: "site.tv", HasLookup: true},
	"xwx.me":    {Suffix: "xwx.me", Name: "FurryBox", URL: "https://www.furry.box/whois/", Parent: "xwx.me", HasLookup: true},
	"furry.box": {Suffix: "furry.box", Name: "FurryBox", URL: "https://www.furry.box/whois/", Parent: "furry.box", HasLookup: true},
}

// PlatformNamespaceError is returned by Parse when the host lives inside a
// platform-run namespace. It carries the platform so callers can explain
// where the record actually lives instead of calling the name unregistered.
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
