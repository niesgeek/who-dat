package dnsq

import (
	"net"
	"strings"
)

// ValidateServer checks a DNS server parameter.
// An IP must be a public unicast address. A hostname is returned lowercase
// for a later lookup; the resolved address is checked again before dialing.
func ValidateServer(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(host, ".")
	if host == "" || strings.ContainsAny(host, " \t/") {
		return "", ErrInvalidServer
	}
	if h, port, err := net.SplitHostPort(host); err == nil {
		if port != "53" {
			return "", ErrInvalidServer
		}
		host = strings.Trim(h, "[]")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !isPublic(ip) {
			return "", ErrPrivateServer
		}
		return ip.String(), nil
	}
	if !hostname(host) {
		return "", ErrInvalidServer
	}
	return strings.ToLower(host), nil
}

func hostname(host string) bool {
	if host == "" || len(host) > 253 || strings.Contains(host, "..") {
		return false
	}
	for _, lab := range strings.Split(host, ".") {
		if lab == "" || len(lab) > 63 {
			return false
		}
		if strings.HasPrefix(lab, "-") || strings.HasSuffix(lab, "-") {
			return false
		}
		for _, r := range lab {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			default:
				return false
			}
		}
	}
	return true
}

func isPublic(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 100 && ip4[1]&0xc0 == 64: // 100.64.0.0/10
			return false
		case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0: // 192.0.0.0/24
			return false
		case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2: // 192.0.2.0/24
			return false
		case ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100: // 198.51.100.0/24
			return false
		case ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113: // 203.0.113.0/24
			return false
		case ip4[0] == 198 && ip4[1]&0xfe == 18: // 198.18.0.0/15
			return false
		case ip4[0] >= 240: // 240.0.0.0/4
			return false
		}
		return true
	}
	// 2001:db8::/32 documentation prefix.
	if len(ip) == 16 && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
		return false
	}
	return true
}
