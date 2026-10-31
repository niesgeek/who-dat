package dnsq

import (
	"fmt"
	"net"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// ParsedName is a query name ready for the wire, plus the label to show people.
type ParsedName struct {
	Name    string // lowercase ASCII, no trailing dot
	Display string // what the person typed, or the canonical IP for a reverse lookup
	Reverse bool
}

// ParseName accepts a hostname, URL, wildcard, underscore label, or IP address.
// An IP is rewritten to its in-addr.arpa or ip6.arpa name and Reverse is set.
func ParseName(raw string) (ParsedName, error) {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "[]")
	s = strings.TrimSuffix(s, ".")
	if i := strings.IndexByte(s, '%'); i >= 0 && strings.Contains(s, ":") {
		s = s[:i]
	}
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " \t") {
		return ParsedName{}, ErrInvalidName
	}
	if ip := net.ParseIP(s); ip != nil {
		arpa, err := reverseName(ip)
		if err != nil {
			return ParsedName{}, err
		}
		return ParsedName{Name: arpa, Display: ip.String(), Reverse: true}, nil
	}
	display := strings.ToLower(s)
	ascii, err := asciiName(display)
	if err != nil {
		return ParsedName{}, err
	}
	return ParsedName{Name: ascii, Display: display}, nil
}

func reverseName(ip net.IP) (string, error) {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0]), nil
	}
	v6 := ip.To16()
	if v6 == nil {
		return "", ErrInvalidName
	}
	nibbles := make([]byte, 0, 32)
	for i := 0; i < 16; i++ {
		nibbles = append(nibbles, hexNibble(v6[i]>>4), hexNibble(v6[i]&0x0f))
	}
	var b strings.Builder
	for i := len(nibbles) - 1; i >= 0; i-- {
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteByte(nibbles[i])
	}
	b.WriteString(".ip6.arpa")
	return b.String(), nil
}

func hexNibble(v byte) byte {
	if v < 10 {
		return '0' + v
	}
	return 'a' + (v - 10)
}

func asciiName(name string) (string, error) {
	if name == "" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return "", ErrInvalidName
	}
	labels := strings.Split(name, ".")
	out := make([]string, len(labels))
	for i, lab := range labels {
		if lab == "" || len(lab) > 63 {
			return "", ErrInvalidName
		}
		if lab == "*" {
			out[i] = lab
			continue
		}
		if asciiLabel(lab) {
			if strings.HasPrefix(lab, "-") || strings.HasSuffix(lab, "-") {
				return "", ErrInvalidName
			}
			out[i] = lab
			continue
		}
		a, err := idna.Lookup.ToASCII(lab)
		if err != nil || a == "" || len(a) > 63 {
			return "", ErrInvalidName
		}
		out[i] = strings.ToLower(a)
	}
	joined := strings.Join(out, ".")
	if len(joined) > 253 {
		return "", ErrInvalidName
	}
	return joined, nil
}

func asciiLabel(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func trimDot(s string) string {
	return strings.TrimSuffix(strings.TrimSpace(s), ".")
}
