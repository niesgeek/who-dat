package dnsq

import (
	"sort"
	"strconv"
	"strings"
)

func ofType(rrs []RR, typ string) []RR {
	out := make([]RR, 0)
	for _, rr := range rrs {
		if rr.Type == typ {
			out = append(out, rr)
		}
	}
	return out
}

func valuesOf(rrs []RR, typ string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, rr := range ofType(rrs, typ) {
		v := strings.ToLower(trimDot(rr.Data))
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sameVals(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func overlaps(a, b []string) bool {
	for _, v := range a {
		for _, w := range b {
			if v == w {
				return true
			}
		}
	}
	return false
}

// compareVals classifies a resolver answer against an authoritative baseline.
// Both slices are treated as sets. "match", "partial", "spread", or "empty".
func compareVals(base, got []string) string {
	if sameVals(base, got) {
		return "match"
	}
	if overlaps(base, got) {
		return "partial"
	}
	if len(got) > 0 {
		return "spread"
	}
	return "empty"
}

func brief(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	n := 2
	if len(vals) < n {
		n = len(vals)
	}
	s := strings.Join(vals[:n], ", ")
	if len(vals) > n {
		s += " (+" + strconv.Itoa(len(vals)-n) + ")"
	}
	return s
}

func hasRRSIG(rrs []RR, covered string) bool {
	for _, rr := range rrs {
		if rr.Type != "RRSIG" {
			continue
		}
		if covered == "" {
			return true
		}
		fields := strings.Fields(rr.Data)
		if len(fields) > 0 && strings.EqualFold(fields[0], covered) {
			return true
		}
	}
	return false
}

type dnssecFacts struct {
	ApexKnown     bool
	DNSKEYQueryOK bool
	DNSKEY        int
	KSK           int
	DSQueryOK     bool
	ApexDS        int
	TLDQueryOK    bool
	TLDDS         int
	HasRRSIG      bool
	AD            *bool
}

// judgeDNSSEC returns a presence-only verdict.
// complete means the records are all there, not that a signature was checked.
func judgeDNSSEC(f dnssecFacts) string {
	if !f.ApexKnown {
		return "no-apex"
	}
	if !f.DNSKEYQueryOK || !f.DSQueryOK {
		return "unknown"
	}
	switch {
	case f.DNSKEY > 0 && f.ApexDS > 0 && f.HasRRSIG:
		return "complete"
	case f.DNSKEY > 0 && f.ApexDS > 0:
		return "incomplete"
	case f.DNSKEY > 0 && f.ApexDS == 0:
		return "self-signed"
	case f.DNSKEY == 0 && f.ApexDS > 0:
		return "broken"
	default:
		return "unsigned"
	}
}

func parseSOA(data string) (SOA, bool) {
	f := strings.Fields(data)
	if len(f) < 7 {
		return SOA{}, false
	}
	nums := make([]uint32, 5)
	for i := 0; i < 5; i++ {
		n, err := strconv.ParseUint(f[2+i], 10, 32)
		if err != nil {
			return SOA{}, false
		}
		nums[i] = uint32(n)
	}
	return SOA{
		MName:   trimDot(f[0]),
		RName:   mailbox(trimDot(f[1])),
		Serial:  nums[0],
		Refresh: nums[1],
		Retry:   nums[2],
		Expire:  nums[3],
		Minimum: nums[4],
	}, true
}

func mailbox(s string) string {
	i := strings.IndexByte(s, '.')
	if i <= 0 {
		return s
	}
	return s[:i] + "@" + s[i+1:]
}

func findSOA(resp *Response) (owner string, soa SOA, ok bool) {
	if resp == nil {
		return "", SOA{}, false
	}
	for _, sec := range [][]RR{resp.Answer, resp.Authority} {
		for _, rr := range sec {
			if rr.Type != "SOA" {
				continue
			}
			parsed, good := parseSOA(rr.Data)
			if !good {
				continue
			}
			return strings.ToLower(trimDot(rr.Name)), parsed, true
		}
	}
	return "", SOA{}, false
}

func nsHosts(resp *Response) []string {
	if resp == nil {
		return nil
	}
	for _, sec := range [][]RR{resp.Answer, resp.Authority} {
		var hosts []string
		seen := map[string]struct{}{}
		for _, rr := range sec {
			if rr.Type != "NS" {
				continue
			}
			h := strings.ToLower(trimDot(rr.Data))
			if h == "" {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			hosts = append(hosts, h)
		}
		if len(hosts) > 0 {
			return hosts
		}
	}
	return nil
}

type serialRow struct {
	Host   string
	Serial *uint32
	MName  string
	Err    string
}

// judgeSerials compares per-server SOA serials.
// Codes: synced, lag, multi, unreachable, none.
func judgeSerials(rows []serialRow) Serials {
	out := Serials{Code: "none", Latest: -1, Lagging: []string{}, Groups: []SerialGroup{}}
	if len(rows) == 0 {
		return out
	}
	groups := map[string][]serialRow{}
	var order []string
	answered := 0
	var latest uint32
	var haveLatest bool
	for _, row := range rows {
		if row.Serial == nil {
			continue
		}
		answered++
		if !haveLatest || *row.Serial > latest {
			latest = *row.Serial
			haveLatest = true
		}
		key := strings.ToLower(row.MName)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], row)
	}
	if answered == 0 {
		out.Code = "unreachable"
		return out
	}
	out.Latest = int64(latest)
	if len(order) > 1 {
		out.Code = "multi"
		for _, key := range order {
			g := groups[key]
			var top uint32
			var hosts []string
			for i, row := range g {
				if i == 0 || *row.Serial > top {
					top = *row.Serial
				}
				hosts = append(hosts, row.Host)
			}
			name := g[0].MName
			if name == "" {
				name = key
			}
			out.Groups = append(out.Groups, SerialGroup{MName: name, Serial: int64(top), Hosts: hosts})
		}
		return out
	}
	for _, row := range rows {
		if row.Serial != nil && *row.Serial != latest {
			out.Lagging = append(out.Lagging, row.Host)
		}
	}
	if len(out.Lagging) > 0 {
		out.Code = "lag"
		return out
	}
	out.Code = "synced"
	return out
}

// judgeDelegation compares parent-delegation NS names with the child zone's own NS set.
func judgeDelegation(parent, child []string, childKnown bool) Delegation {
	d := Delegation{
		Parent:     normNames(parent),
		Child:      []string{},
		ChildKnown: childKnown,
		OnlyParent: []string{},
		OnlyChild:  []string{},
		Code:       "child-unavailable",
	}
	if !childKnown {
		return d
	}
	d.Child = normNames(child)
	parentSet := map[string]struct{}{}
	for _, n := range d.Parent {
		parentSet[n] = struct{}{}
	}
	childSet := map[string]struct{}{}
	for _, n := range d.Child {
		childSet[n] = struct{}{}
	}
	for _, n := range d.Parent {
		if _, ok := childSet[n]; !ok {
			d.OnlyParent = append(d.OnlyParent, n)
		}
	}
	for _, n := range d.Child {
		if _, ok := parentSet[n]; !ok {
			d.OnlyChild = append(d.OnlyChild, n)
		}
	}
	d.Consistent = len(d.OnlyParent) == 0 && len(d.OnlyChild) == 0
	if d.Consistent {
		d.Code = "match"
	} else {
		d.Code = "mismatch"
	}
	return d
}

func normNames(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, n := range in {
		n = strings.ToLower(trimDot(n))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func inBailiwick(host, apex string) bool {
	host = strings.ToLower(trimDot(host))
	apex = strings.ToLower(trimDot(apex))
	if host == "" || apex == "" {
		return false
	}
	return host == apex || strings.HasSuffix(host, "."+apex)
}

func kskCount(rrs []RR) (total, ksk int) {
	for _, rr := range ofType(rrs, "DNSKEY") {
		total++
		fields := strings.Fields(rr.Data)
		if len(fields) == 0 {
			continue
		}
		flags, err := strconv.ParseUint(fields[0], 10, 16)
		if err == nil && flags&0x0100 != 0 {
			ksk++
		}
	}
	return total, ksk
}

func adBit(resps ...*Response) *bool {
	saw := false
	ad := false
	for _, r := range resps {
		if r == nil || r.Rcode == "" {
			continue
		}
		saw = true
		if r.Flags.AD {
			ad = true
		}
	}
	if !saw {
		return nil
	}
	return &ad
}
