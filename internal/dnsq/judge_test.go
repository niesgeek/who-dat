package dnsq

import "testing"

func TestCompareVals(t *testing.T) {
	if compareVals([]string{"a", "b"}, []string{"a", "b"}) != "match" {
		t.Fatal("match")
	}
	if compareVals([]string{"a", "b"}, []string{"b"}) != "partial" {
		t.Fatal("partial")
	}
	if compareVals([]string{"a"}, []string{"c"}) != "spread" {
		t.Fatal("spread")
	}
	if compareVals([]string{"a"}, nil) != "empty" {
		t.Fatal("empty")
	}
}

func TestJudgeDNSSEC(t *testing.T) {
	base := dnssecFacts{ApexKnown: true, DNSKEYQueryOK: true, DSQueryOK: true}
	cases := []struct {
		name string
		edit func(*dnssecFacts)
		want string
	}{
		{"complete", func(f *dnssecFacts) { f.DNSKEY, f.ApexDS, f.HasRRSIG = 2, 1, true }, "complete"},
		{"incomplete", func(f *dnssecFacts) { f.DNSKEY, f.ApexDS = 1, 1 }, "incomplete"},
		{"self-signed", func(f *dnssecFacts) { f.DNSKEY = 1 }, "self-signed"},
		{"broken", func(f *dnssecFacts) { f.ApexDS = 1 }, "broken"},
		{"unsigned", func(f *dnssecFacts) {}, "unsigned"},
		{"unknown", func(f *dnssecFacts) { f.DNSKEYQueryOK = false }, "unknown"},
		{"no apex", func(f *dnssecFacts) { f.ApexKnown = false }, "no-apex"},
	}
	for _, tc := range cases {
		f := base
		tc.edit(&f)
		if got := judgeDNSSEC(f); got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestJudgeSerialsAndDelegation(t *testing.T) {
	s1, s2 := uint32(200), uint32(100)
	lag := judgeSerials([]serialRow{
		{Host: "ns1.example.net", Serial: &s1, MName: "ns1.example.net"},
		{Host: "ns2.example.net", Serial: &s2, MName: "ns1.example.net"},
	})
	if lag.Code != "lag" || len(lag.Lagging) != 1 || lag.Lagging[0] != "ns2.example.net" {
		t.Fatalf("lag = %+v", lag)
	}

	m1, m2 := "ns1.example.net", "ns.other.net"
	multi := judgeSerials([]serialRow{
		{Host: "ns1.example.net", Serial: &s1, MName: m1},
		{Host: "ns.other.net", Serial: &s2, MName: m2},
	})
	if multi.Code != "multi" || len(multi.Groups) != 2 {
		t.Fatalf("multi = %+v", multi)
	}

	none := judgeSerials(nil)
	if none.Code != "none" {
		t.Fatal(none.Code)
	}
	down := judgeSerials([]serialRow{{Host: "ns1.example.net", Err: "timeout"}})
	if down.Code != "unreachable" {
		t.Fatal(down.Code)
	}

	ok := judgeDelegation(
		[]string{"ns2.example.net", "ns1.example.net."},
		[]string{"NS1.example.net", "ns2.example.net"},
		true,
	)
	if !ok.Consistent || ok.Code != "match" {
		t.Fatalf("delegation = %+v", ok)
	}
	bad := judgeDelegation([]string{"ns1.example.net", "ns2.example.net"}, []string{"ns1.example.net"}, true)
	if bad.Code != "mismatch" || len(bad.OnlyParent) != 1 || bad.OnlyParent[0] != "ns2.example.net" {
		t.Fatalf("mismatch = %+v", bad)
	}
	if judgeDelegation([]string{"ns1.example.net"}, nil, false).Code != "child-unavailable" {
		t.Fatal("child")
	}
	if !inBailiwick("ns1.example.com", "example.com") || inBailiwick("ns1.example.net", "example.com") {
		t.Fatal("bailiwick")
	}
}

func TestParseSOA(t *testing.T) {
	soa, ok := parseSOA("ns1.example.net. hostmaster.example.com. 202 7200 3600 1209600 300")
	if !ok || soa.Serial != 202 || soa.MName != "ns1.example.net" || soa.RName != "hostmaster@example.com" {
		t.Fatalf("%+v %v", soa, ok)
	}
}
