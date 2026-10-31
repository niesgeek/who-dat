package dnsq

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Query is one DNS question.
type Query struct {
	Name    string
	Type    string
	Server  string
	DNSSEC  bool
	RD      bool
	Timeout time.Duration
}

// RR is one resource record in presentation form.
type RR struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

// Flags are the response header bits the laboratory surfaces.
type Flags struct {
	AA bool `json:"aa"`
	AD bool `json:"ad"`
	RD bool `json:"rd"`
	RA bool `json:"ra"`
	TC bool `json:"tc"`
	CD bool `json:"cd"`
}

// Response is the JSON body of GET /api/dns.
type Response struct {
	OK                     bool   `json:"ok"`
	Server                 string `json:"server"`
	Transport              string `json:"transport"`
	FellBackFromTruncation bool   `json:"fellBackFromTruncation"`
	ElapsedMS              int64  `json:"elapsed_ms"`
	Name                   string `json:"name"`
	Type                   string `json:"type"`
	Rcode                  string `json:"rcode"`
	Flags                  Flags  `json:"flags"`
	Answer                 []RR   `json:"answer"`
	Authority              []RR   `json:"authority"`
	Additional             []RR   `json:"additional"`
	DNSSEC                 bool   `json:"dnssec"`
	TS                     int64  `json:"ts"`
}

// Text renders a dig-style summary. The comment line is metadata; the body is the answer section.
func (r *Response) Text() string {
	if r == nil {
		return "# error\n"
	}
	aa, ad := 0, 0
	if r.Flags.AA {
		aa = 1
	}
	if r.Flags.AD {
		ad = 1
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s @%s (%s, %dms, rcode=%s, aa=%d, ad=%d)\n",
		trimDot(r.Name), r.Server, r.Transport, r.ElapsedMS, r.Rcode, aa, ad)
	for _, rr := range r.Answer {
		data := rr.Data
		if rr.Type == "TXT" {
			data = `"` + strings.ReplaceAll(strings.ReplaceAll(data, `\`, `\\`), `"`, `\"`) + `"`
		}
		fmt.Fprintf(&b, "%s\t%d\tIN\t%s\t%s\n", rr.Name, rr.TTL, rr.Type, data)
	}
	return b.String()
}

// PresenceDisclaimer is returned with every laboratory report.
// Chain completeness is not signature validity.
const PresenceDisclaimer = "DNSSEC results report whether DS, DNSKEY, and RRSIG records are present and whether a resolver set the AD bit. Signatures are not checked here. A complete chain is not a validated signature."

var typeCodes = map[string]uint16{
	"A":      dns.TypeA,
	"AAAA":   dns.TypeAAAA,
	"CNAME":  dns.TypeCNAME,
	"MX":     dns.TypeMX,
	"TXT":    dns.TypeTXT,
	"NS":     dns.TypeNS,
	"SOA":    dns.TypeSOA,
	"CAA":    dns.TypeCAA,
	"SRV":    dns.TypeSRV,
	"PTR":    dns.TypePTR,
	"DS":     dns.TypeDS,
	"DNSKEY": dns.TypeDNSKEY,
	"RRSIG":  dns.TypeRRSIG,
}

func canonicalType(raw string) (string, uint16, error) {
	t := strings.ToUpper(strings.TrimSpace(raw))
	code, ok := typeCodes[t]
	if !ok {
		return "", 0, ErrInvalidType
	}
	return t, code, nil
}
