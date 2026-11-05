package server

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// connection is what this process can see on the request itself.
// ASN, ISP, and the visitor's TLS version are filled only when the
// platform actually attached them. Vercel does not, so those stay empty
// rather than being looked up from a third-party database.
type connection struct {
	IP             string
	Type           string
	ASN            *int
	Org            string
	City           string
	Region         string
	Country        string
	Continent      string
	Colo           string
	TLSVersion     string
	HTTPProtocol   string
	ForwardedProto string
	Edge           bool
}

func readConnection(r *http.Request) connection {
	ip := visitorIP(r)
	kind := ""
	if parsed := net.ParseIP(ip); parsed != nil {
		if parsed.To4() != nil {
			kind = "IPv4"
		} else {
			kind = "IPv6"
		}
	}
	country := headerFirst(r, "X-Vercel-IP-Country", "CF-IPCountry")
	region := headerFirst(r, "X-Vercel-IP-Country-Region", "CF-Region")
	city := unescapeHeader(headerFirst(r, "X-Vercel-IP-City", "CF-IPCity"))
	continent := headerFirst(r, "X-Vercel-IP-Continent")
	colo := vercelPop(r.Header.Get("X-Vercel-Id"))
	if colo == "" {
		colo = cloudflareColo(r.Header.Get("CF-Ray"))
	}
	tlsVersion := ""
	if r.TLS != nil {
		tlsVersion = tlsName(r.TLS.Version)
	}
	c := connection{
		IP:             ip,
		Type:           kind,
		City:           city,
		Region:         region,
		Country:        country,
		Continent:      continent,
		Colo:           colo,
		TLSVersion:     tlsVersion,
		HTTPProtocol:   r.Proto,
		ForwardedProto: r.Header.Get("X-Forwarded-Proto"),
	}
	// Only headers the edge itself sets. A visitor-supplied X-ASN is ignored
	// so the panel cannot be talked into showing a fake network.
	c.Edge = c.Country != "" || c.City != "" || c.Continent != "" || c.Colo != "" || c.Region != ""
	return c
}

func (c connection) placeLine() string {
	var parts []string
	for _, part := range []string{c.Country, c.Region, c.City} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, " · ")
}

func (c connection) unavailable() []string {
	out := []string{}
	if c.ASN == nil {
		out = append(out, "asn")
	}
	if c.Org == "" {
		out = append(out, "org")
	}
	if c.TLSVersion == "" {
		out = append(out, "tlsVersion")
	}
	return out
}

func (c connection) public() map[string]any {
	return map[string]any{
		"ip":             c.IP,
		"type":           c.Type,
		"version":        c.Type,
		"asn":            c.ASN,
		"org":            c.Org,
		"city":           c.City,
		"region":         c.Region,
		"country":        c.Country,
		"country_code":   c.Country,
		"continent":      c.Continent,
		"colo":           c.Colo,
		"pop":            c.Colo,
		"tlsVersion":     c.TLSVersion,
		"tls":            c.TLSVersion,
		"httpProtocol":   c.HTTPProtocol,
		"protocol":       c.HTTPProtocol,
		"forwardedProto": c.ForwardedProto,
		"edge":           c.Edge,
		"ts":             time.Now().UnixMilli(),
		"platformHints":  c.Edge,
		"source":         "connection",
		"thirdPartyGeo":  false,
		"unavailable":    c.unavailable(),
	}
}

// visitorIP prefers the address the platform stamped, then the proxy chain.
func visitorIP(r *http.Request) string {
	if ip := firstForwarded(r.Header.Get("X-Vercel-Forwarded-For")); ip != "" {
		return ip
	}
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	return clientIP(r)
}

func firstForwarded(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if i := strings.IndexByte(raw, ','); i > 0 {
		return strings.TrimSpace(raw[:i])
	}
	return raw
}
