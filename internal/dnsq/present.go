package dnsq

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func nowMillis() int64 { return time.Now().UnixMilli() }

func fromMsg(name, typ, server string, dnssec bool, msg *dns.Msg, transport string, truncFallback bool, elapsedMS int64) *Response {
	if msg == nil {
		return nil
	}
	rcode := dns.RcodeToString[msg.Rcode]
	if rcode == "" {
		rcode = fmt.Sprintf("RCODE%d", msg.Rcode)
	}
	if elapsedMS < 0 {
		elapsedMS = 0
	}
	return &Response{
		OK:                     true,
		Server:                 server,
		Transport:              transport,
		FellBackFromTruncation: truncFallback,
		ElapsedMS:              elapsedMS,
		Name:                   trimDot(name),
		Type:                   typ,
		Rcode:                  rcode,
		Flags: Flags{
			AA: msg.Authoritative,
			AD: msg.AuthenticatedData,
			RD: msg.RecursionDesired,
			RA: msg.RecursionAvailable,
			TC: msg.Truncated,
			CD: msg.CheckingDisabled,
		},
		Answer:     section(msg.Answer),
		Authority:  section(msg.Ns),
		Additional: section(msg.Extra),
		DNSSEC:     dnssec,
		TS:         nowMillis(),
	}
}

func section(rrs []dns.RR) []RR {
	out := make([]RR, 0)
	for _, rr := range rrs {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		h := rr.Header()
		typ := dns.TypeToString[h.Rrtype]
		if typ == "" {
			typ = fmt.Sprintf("TYPE%d", h.Rrtype)
		}
		out = append(out, RR{
			Name: h.Name,
			Type: typ,
			TTL:  h.Ttl,
			Data: rrData(rr),
		})
	}
	return out
}

func rrData(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		if v.A == nil {
			return ""
		}
		return v.A.String()
	case *dns.AAAA:
		if v.AAAA == nil {
			return ""
		}
		return v.AAAA.String()
	case *dns.CNAME:
		return v.Target
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, v.Mx)
	case *dns.TXT:
		return strings.Join(v.Txt, "")
	case *dns.NS:
		return v.Ns
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d", v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *dns.CAA:
		return fmt.Sprintf("%d %s %q", v.Flag, v.Tag, v.Value)
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
	case *dns.PTR:
		return v.Ptr
	case *dns.DS:
		return fmt.Sprintf("%d %d %d %s", v.KeyTag, v.Algorithm, v.DigestType, v.Digest)
	case *dns.DNSKEY:
		return fmt.Sprintf("%d %d %d %s", v.Flags, v.Protocol, v.Algorithm, v.PublicKey)
	case *dns.RRSIG:
		return fmt.Sprintf("%s %d %d %d %d %d %d %s %s",
			dns.TypeToString[v.TypeCovered], v.Algorithm, v.Labels, v.OrigTtl,
			v.Expiration, v.Inception, v.KeyTag, v.SignerName, v.Signature)
	default:
		return rdataFallback(rr)
	}
}

func rdataFallback(rr dns.RR) string {
	s := rr.String()
	typ := dns.TypeToString[rr.Header().Rrtype]
	fields := strings.Fields(s)
	for i, f := range fields {
		if f == typ && i+1 < len(fields) {
			return strings.Join(fields[i+1:], " ")
		}
	}
	return s
}
