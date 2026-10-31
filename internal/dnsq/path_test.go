package dnsq

import "testing"

func TestBuildPathLitChain(t *testing.T) {
	serial := uint32(2026100419)
	prop := Propagation{
		Baseline: "authoritative",
		Rows: []PropRow{
			{Role: "authoritative", State: "reference", Name: "a.example.net"},
			{Role: "resolver", State: "match"},
			{Role: "resolver", State: "match"},
			{Role: "resolver", State: "match"},
			{Role: "resolver", State: "match"},
			{Role: "resolver", State: "match"},
		},
	}
	sec := DNSSEC{Level: "complete", Apex: "example.sb", ApexDS: 1, DNSKEY: 2, RRSIG: true}
	ns := Nameservers{Servers: []NSServer{
		{Host: "a.dns.sb", Serial: &serial, AA: true},
	}}
	path := BuildPath(ClientHint{IP: "203.88.115.47", Place: "US", Pop: "lax"}, prop, sec, ns)
	if path.Badge != "complete" || len(path.Nodes) != 5 {
		t.Fatalf("path = %+v", path)
	}
	want := []struct{ key, state, code string }{
		{"you", "ok", "address"},
		{"resolver", "ok", "agree"},
		{"authority", "ok", "aa"},
		{"tld", "ok", "ds"},
		{"root", "ok", "anchor"},
	}
	for i, w := range want {
		n := path.Nodes[i]
		if n.Key != w.key || n.State != w.state || n.Code != w.code {
			t.Errorf("node %d = %+v, want %s %s %s", i, n, w.key, w.state, w.code)
		}
	}
	if path.Nodes[0].Name != "203.88.115.47" || path.Nodes[0].Detail != "US · lax" {
		t.Fatalf("you = %+v", path.Nodes[0])
	}
	if path.Nodes[1].Exact != 5 || path.Nodes[1].Total != 5 {
		t.Fatalf("resolvers = %+v", path.Nodes[1])
	}
	if path.Nodes[2].Name != "a.dns.sb" || path.Nodes[2].Serial == nil || *path.Nodes[2].Serial != serial || !path.Nodes[2].AA {
		t.Fatalf("auth = %+v", path.Nodes[2])
	}
	if path.Nodes[3].Name != "sb" || path.Nodes[3].DS != 1 {
		t.Fatalf("tld = %+v", path.Nodes[3])
	}
}

func TestBuildPathDimWhenUnreachable(t *testing.T) {
	prop := Propagation{
		Baseline: "resolver",
		Rows: []PropRow{
			{Role: "resolver", State: "baseline"},
			{Role: "resolver", State: "match"},
			{Role: "resolver", State: "down"},
		},
	}
	sec := DNSSEC{Level: "unsigned", Apex: "example.com", DNSKEYQueryOK: true, DSQueryOK: true}
	ns := Nameservers{Servers: []NSServer{
		{Host: "ns1.example.net", Error: "timeout"},
		{Host: "ns2.example.net", Error: "timeout"},
	}}
	path := BuildPath(ClientHint{}, prop, sec, ns)
	if path.Nodes[0].State != "unknown" || path.Nodes[0].Code != "missing" {
		t.Fatalf("you = %+v", path.Nodes[0])
	}
	if path.Nodes[1].State != "ok" || path.Nodes[1].Exact != 2 || path.Nodes[1].Failed != 1 {
		t.Fatalf("resolver = %+v", path.Nodes[1])
	}
	if path.Nodes[2].State != "unknown" || path.Nodes[2].Code != "unreachable" || path.Nodes[2].Detail != "timeout" {
		t.Fatalf("auth = %+v", path.Nodes[2])
	}
	if path.Nodes[3].State != "unknown" || path.Nodes[3].Code != "unsigned" || path.Nodes[3].Name != "com" {
		t.Fatalf("tld = %+v", path.Nodes[3])
	}
}

func TestBuildPathEmptyAnswersAreBad(t *testing.T) {
	prop := Propagation{
		Baseline: "authoritative",
		Rows: []PropRow{
			{Role: "authoritative", State: "reference"},
			{Role: "resolver", State: "empty"},
			{Role: "resolver", State: "match"},
		},
	}
	path := BuildPath(ClientHint{}, prop, DNSSEC{Level: "no-apex"}, Nameservers{})
	if path.Nodes[1].State != "bad" || path.Nodes[1].Code != "empty" {
		t.Fatalf("resolver = %+v", path.Nodes[1])
	}
	if path.Nodes[2].Code != "none" || path.Nodes[3].Code != "unchecked" {
		t.Fatalf("auth/tld = %+v %+v", path.Nodes[2], path.Nodes[3])
	}
}
