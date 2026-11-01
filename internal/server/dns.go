package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lissy93/who-dat/internal/dnsq"
)

func (s *server) handleDNSPage(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = "/dns.html"
	s.files.ServeHTTP(w, r)
}

func (s *server) handleDNS(w http.ResponseWriter, r *http.Request) {
	setDNSHeaders(w)
	q, err := s.dnsQuery(r)
	if err != nil {
		writeDNSError(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), q.Timeout+time.Second)
	defer cancel()
	resp, err := s.dns.Query(ctx, q)
	if err != nil {
		writeDNSError(w, r, err)
		return
	}
	if wantsDNSText(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, resp.Text())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleDNSLab(w http.ResponseWriter, r *http.Request) {
	setDNSHeaders(w)
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = strings.TrimSpace(r.URL.Query().Get("q"))
	}
	if name == "" {
		writeDNSError(w, r, dnsq.ErrInvalidName)
		return
	}
	serverName := strings.TrimSpace(r.URL.Query().Get("server"))
	if serverName == "" {
		serverName = s.cfg.DNSServer
	}
	if serverName == "" {
		serverName = "8.8.8.8"
	}
	if _, err := dnsq.ValidateServer(serverName); err != nil {
		writeDNSError(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 9*time.Second)
	defer cancel()
	report, err := dnsq.RunLab(ctx, s.dns, dnsq.LabInput{
		Name:    name,
		Type:    r.URL.Query().Get("type"),
		Server:  serverName,
		Timeout: 2 * time.Second,
		Client:  clientHint(r),
	})
	if err != nil {
		writeDNSError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *server) dnsQuery(r *http.Request) (dnsq.Query, error) {
	vals := r.URL.Query()
	name := strings.TrimSpace(vals.Get("name"))
	if name == "" {
		name = strings.TrimSpace(vals.Get("q"))
	}
	if name == "" {
		return dnsq.Query{}, dnsq.ErrInvalidName
	}
	typ := strings.TrimSpace(vals.Get("type"))
	if typ == "" {
		typ = "A"
	}
	if strings.EqualFold(typ, "ALL") {
		return dnsq.Query{}, dnsq.ErrInvalidType
	}
	serverName := strings.TrimSpace(vals.Get("server"))
	if serverName == "" {
		serverName = s.cfg.DNSServer
	}
	if serverName == "" {
		serverName = "8.8.8.8"
	}
	if _, err := dnsq.ValidateServer(serverName); err != nil {
		return dnsq.Query{}, err
	}
	dnssec, err := parseFlag(vals.Get("dnssec"), true)
	if err != nil {
		return dnsq.Query{}, errBadParam
	}
	rd, err := parseFlag(vals.Get("rd"), true)
	if err != nil {
		return dnsq.Query{}, errBadParam
	}
	timeout := s.cfg.DNSTimeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	if raw := strings.TrimSpace(vals.Get("timeout")); raw != "" {
		ms, conv := strconv.Atoi(raw)
		if conv != nil || ms <= 0 {
			return dnsq.Query{}, errBadParam
		}
		if ms < 200 {
			ms = 200
		}
		if ms > 8000 {
			ms = 8000
		}
		timeout = time.Duration(ms) * time.Millisecond
	}
	return dnsq.Query{
		Name:    name,
		Type:    typ,
		Server:  serverName,
		DNSSEC:  dnssec,
		RD:      rd,
		Timeout: timeout,
	}, nil
}

var errBadParam = errors.New("bad dns parameter")

func parseFlag(raw string, def bool) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return def, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, errBadParam
	}
}

func wantsDNSText(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) {
	case "text", "dig", "plain":
		return true
	case "json":
		return false
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "text/plain") && !strings.Contains(accept, "application/json") {
		return true
	}
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	return strings.Contains(ua, "curl/") || strings.HasPrefix(ua, "wget/")
}

func setDNSHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Accept, User-Agent")
}

func writeDNSError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, msg := dnsStatus(err)
	setDNSHeaders(w)
	if wantsDNSText(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, "# error "+code+": "+msg+"\n")
		return
	}
	writeJSON(w, status, map[string]any{
		"ok":    false,
		"error": map[string]string{"code": code, "message": msg},
	})
}

func dnsStatus(err error) (int, string, string) {
	switch {
	case errors.Is(err, dnsq.ErrInvalidName):
		return http.StatusBadRequest, "INVALID_NAME", "could not parse a DNS name"
	case errors.Is(err, dnsq.ErrInvalidType):
		return http.StatusBadRequest, "INVALID_TYPE", "unsupported DNS type"
	case errors.Is(err, dnsq.ErrInvalidServer):
		return http.StatusBadRequest, "INVALID_SERVER", "server must be a public DNS hostname or address"
	case errors.Is(err, dnsq.ErrPrivateServer):
		return http.StatusBadRequest, "PRIVATE_SERVER", "refusing a non-public DNS server address"
	case errors.Is(err, errBadParam):
		return http.StatusBadRequest, "BAD_PARAMETER", "check dnssec, rd, and timeout"
	case errors.Is(err, dnsq.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "UPSTREAM_TIMEOUT", "DNS server timed out"
	default:
		return http.StatusBadGateway, "UPSTREAM_ERROR", "DNS server unreachable or returned an invalid response"
	}
}

func clientHint(r *http.Request) dnsq.ClientHint {
	country := headerFirst(r, "X-Vercel-IP-Country", "CF-IPCountry")
	region := headerFirst(r, "X-Vercel-IP-Country-Region", "CF-Region")
	city := unescapeHeader(headerFirst(r, "X-Vercel-IP-City", "CF-IPCity"))
	var place []string
	for _, part := range []string{country, region, city} {
		if part != "" {
			place = append(place, part)
		}
	}
	pop := vercelPop(r.Header.Get("X-Vercel-Id"))
	if pop == "" {
		pop = cloudflareColo(r.Header.Get("CF-Ray"))
	}
	return dnsq.ClientHint{IP: clientIP(r), Place: strings.Join(place, " · "), Pop: pop}
}

func (s *server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	setDNSHeaders(w)
	hint := clientHint(r)
	ip := hint.IP
	version := ""
	if parsed := net.ParseIP(ip); parsed != nil {
		if parsed.To4() != nil {
			version = "IPv4"
		} else {
			version = "IPv6"
		}
	}
	country := headerFirst(r, "X-Vercel-IP-Country", "CF-IPCountry")
	region := headerFirst(r, "X-Vercel-IP-Country-Region", "CF-Region")
	city := unescapeHeader(headerFirst(r, "X-Vercel-IP-City", "CF-IPCity"))
	pop := vercelPop(r.Header.Get("X-Vercel-Id"))
	if pop == "" {
		pop = cloudflareColo(r.Header.Get("CF-Ray"))
	}
	tlsVersion := ""
	if r.TLS != nil {
		tlsVersion = tlsName(r.TLS.Version)
	}
	proto := r.Proto
	forwarded := r.Header.Get("X-Forwarded-Proto")
	hints := country != "" || region != "" || city != "" || pop != ""
	writeJSON(w, http.StatusOK, map[string]any{
		"ip":             ip,
		"version":        version,
		"country":        country,
		"region":         region,
		"city":           city,
		"protocol":       proto,
		"tls":            tlsVersion,
		"forwardedProto": forwarded,
		"pop":            pop,
		"platformHints":  hints,
		"source":         "connection",
		"thirdPartyGeo":  false,
	})
}

func headerFirst(r *http.Request, keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(r.Header.Get(key)); v != "" {
			return v
		}
	}
	return ""
}

func unescapeHeader(v string) string {
	if v == "" {
		return ""
	}
	if out, err := url.PathUnescape(v); err == nil {
		return out
	}
	return v
}

func vercelPop(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if i := strings.Index(id, "::"); i > 0 {
		return id[:i]
	}
	return id
}

func cloudflareColo(ray string) string {
	if i := strings.LastIndex(ray, "-"); i >= 0 && i+1 < len(ray) {
		colo := ray[i+1:]
		if len(colo) == 3 {
			return colo
		}
	}
	return ""
}

func tlsName(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS1.0"
	case 0x0302:
		return "TLS1.1"
	case 0x0303:
		return "TLS1.2"
	case 0x0304:
		return "TLS1.3"
	default:
		if v == 0 {
			return ""
		}
		return "TLS"
	}
}
