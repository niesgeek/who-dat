package dnsq

import "strings"

// Path is the left-to-right resolution strip: the client, recursive
// resolvers, authoritative servers, the TLD, and the root.
// States are "ok", "bad", or "unknown". Lighting a node means that hop
// produced a fact, not that a signature was checked.
type Path struct {
	Badge string     `json:"badge"`
	Nodes []PathNode `json:"nodes"`
}

// PathNode is one hop. Code is the stable token; Name, Detail, and the
// counts are what the page turns into a sentence.
type PathNode struct {
	Key    string  `json:"key"`
	State  string  `json:"state"`
	Code   string  `json:"code"`
	Name   string  `json:"name,omitempty"`
	Detail string  `json:"detail,omitempty"`
	Exact  int     `json:"exact,omitempty"`
	Total  int     `json:"total,omitempty"`
	Failed int     `json:"failed,omitempty"`
	Serial *uint32 `json:"serial,omitempty"`
	DS     int     `json:"ds,omitempty"`
	AA     bool    `json:"aa,omitempty"`
}

// ClientHint is the visitor's own connection, read from the request that
// asked for the laboratory report. It is not a location lookup.
type ClientHint struct {
	IP    string
	Place string
	Pop   string
}

// BuildPath summarises a finished report as five hops.
func BuildPath(client ClientHint, prop Propagation, sec DNSSEC, ns Nameservers) Path {
	return Path{
		Badge: sec.Level,
		Nodes: []PathNode{
			youNode(client),
			resolverNode(prop),
			authNode(ns),
			tldNode(sec),
			{Key: "root", State: "ok", Code: "anchor", Name: "."},
		},
	}
}

func youNode(c ClientHint) PathNode {
	n := PathNode{Key: "you", State: "unknown", Code: "missing"}
	ip := strings.TrimSpace(c.IP)
	if ip == "" {
		return n
	}
	n.State = "ok"
	n.Code = "address"
	n.Name = ip
	var bits []string
	if p := strings.TrimSpace(c.Place); p != "" {
		bits = append(bits, p)
	}
	if p := strings.TrimSpace(c.Pop); p != "" {
		bits = append(bits, p)
	}
	n.Detail = strings.Join(bits, " · ")
	return n
}

func resolverNode(prop Propagation) PathNode {
	n := PathNode{Key: "resolver", State: "unknown", Code: "none"}
	hasBase := prop.Baseline == "authoritative" || prop.Baseline == "resolver"
	for _, row := range prop.Rows {
		if row.Role == "authoritative" || row.State == "reference" {
			continue
		}
		switch row.State {
		case "match", "baseline":
			n.Total++
			n.Exact++
		case "partial", "spread":
			n.Total++
		case "empty":
			n.Total++
		case "down", "fail":
			n.Failed++
		}
	}
	if !hasBase || n.Total == 0 {
		return n
	}
	switch {
	case n.Exact == n.Total:
		n.State, n.Code = "ok", "agree"
	case n.Exact == 0 && n.Total > 0 && countEmpty(prop) == n.Total:
		n.State, n.Code = "bad", "empty"
	case countEmpty(prop) > 0:
		n.State, n.Code = "bad", "empty"
	default:
		n.State, n.Code = "unknown", "mixed"
	}
	return n
}

func countEmpty(prop Propagation) int {
	n := 0
	for _, row := range prop.Rows {
		if row.Role != "authoritative" && row.State == "empty" {
			n++
		}
	}
	return n
}

func authNode(ns Nameservers) PathNode {
	n := PathNode{Key: "authority", State: "unknown", Code: "none"}
	if len(ns.Servers) == 0 {
		return n
	}
	n.Name = ns.Servers[0].Host
	var blocked int
	for i := range ns.Servers {
		s := ns.Servers[i]
		if s.Serial != nil && s.AA {
			if n.Code != "aa" {
				n.State = "ok"
				n.Code = "aa"
				n.Name = s.Host
				serial := *s.Serial
				n.Serial = &serial
				n.AA = true
			}
			continue
		}
		if s.Serial == nil && s.Error != "" {
			blocked++
			if n.Detail == "" {
				n.Detail = s.Error
			}
		}
	}
	if n.Code == "aa" {
		n.Detail = ""
		return n
	}
	if blocked == len(ns.Servers) {
		n.State, n.Code = "unknown", "unreachable"
		return n
	}
	n.State, n.Code = "bad", "no-answer"
	return n
}

func tldNode(sec DNSSEC) PathNode {
	n := PathNode{Key: "tld", State: "unknown", Code: "unchecked", Name: tldOf(sec.Apex), DS: sec.ApexDS}
	if sec.ApexDS > 0 {
		n.State, n.Code = "ok", "ds"
		return n
	}
	switch sec.Level {
	case "no-apex", "unknown", "":
		return n
	case "self-signed":
		n.Code = "dnskey-only"
		return n
	default:
		if sec.DNSKEY > 0 {
			n.Code = "dnskey-only"
			return n
		}
		n.Code = "unsigned"
		return n
	}
}

func tldOf(apex string) string {
	apex = strings.Trim(strings.TrimSpace(apex), ".")
	if apex == "" {
		return ""
	}
	if i := strings.LastIndex(apex, "."); i >= 0 && i+1 < len(apex) {
		return apex[i+1:]
	}
	return apex
}
