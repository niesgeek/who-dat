package dnsq

import (
	"context"
	"strings"
	"testing"
	"time"
)

type memQR struct {
	hit map[string]*Response
	err map[string]error
}

func (m memQR) Query(_ context.Context, q Query) (*Response, error) {
	k := labKey(q)
	if m.err != nil {
		if err, ok := m.err[k]; ok {
			return nil, err
		}
	}
	if m.hit != nil {
		if r, ok := m.hit[k]; ok {
			cp := *r
			return &cp, nil
		}
	}
	return &Response{
		OK: true, Server: q.Server, Name: q.Name, Type: q.Type, Rcode: "NOERROR",
		Answer: []RR{}, Authority: []RR{}, Additional: []RR{},
	}, nil
}

func labKey(q Query) string {
	rd := "0"
	if q.RD {
		rd = "1"
	}
	return strings.ToLower(trimDot(q.Name)) + " " + strings.ToUpper(q.Type) + " @" + q.Server + " rd=" + rd
}

func put(m memQR, name, typ, server string, rd bool, resp *Response) {
	q := Query{Name: name, Type: typ, Server: server, RD: rd}
	m.hit[labKey(q)] = resp
}

func rr(name, typ, data string) RR {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return RR{Name: name, Type: typ, TTL: 300, Data: data}
}

func resp(server, name, typ, rcode string, aa, ad bool, answer ...RR) *Response {
	if answer == nil {
		answer = []RR{}
	}
	return &Response{
		OK: true, Server: server, Name: name, Type: typ, Rcode: rcode,
		Flags:      Flags{AA: aa, AD: ad, RD: !aa, RA: !aa},
		Answer:     answer,
		Authority:  []RR{},
		Additional: []RR{},
		ElapsedMS:  12,
	}
}

func signedZone() memQR {
	m := memQR{hit: map[string]*Response{}}
	soa := "ns1.example.net. hostmaster.example.com. 202 7200 3600 1209600 300"
	put(m, "example.com", "A", "8.8.8.8", true, resp("8.8.8.8", "example.com", "A", "NOERROR", false, true,
		rr("example.com", "A", "192.0.2.10"),
		rr("example.com", "RRSIG", "A 13 2 300 1793538503 1793358503 34505 example.com. eHh4"),
	))
	put(m, "example.com", "A", "1.1.1.1", true, resp("1.1.1.1", "example.com", "A", "NOERROR", false, true,
		rr("example.com", "A", "192.0.2.10"),
	))
	put(m, "example.com", "SOA", "8.8.8.8", true, resp("8.8.8.8", "example.com", "SOA", "NOERROR", false, true,
		rr("example.com", "SOA", soa),
	))
	put(m, "example.com", "NS", "8.8.8.8", true, resp("8.8.8.8", "example.com", "NS", "NOERROR", false, true,
		rr("example.com", "NS", "ns1.example.net."),
		rr("example.com", "NS", "ns2.example.net."),
	))
	put(m, "ns1.example.net", "A", "8.8.8.8", true, resp("8.8.8.8", "ns1.example.net", "A", "NOERROR", false, false,
		rr("ns1.example.net", "A", "1.2.3.4"),
	))
	put(m, "ns2.example.net", "A", "8.8.8.8", true, resp("8.8.8.8", "ns2.example.net", "A", "NOERROR", false, false,
		rr("ns2.example.net", "A", "1.2.3.5"),
	))
	for _, ip := range []string{"1.2.3.4", "1.2.3.5"} {
		put(m, "example.com", "A", ip, false, resp(ip, "example.com", "A", "NOERROR", true, false,
			rr("example.com", "A", "192.0.2.10"),
		))
		put(m, "example.com", "SOA", ip, false, resp(ip, "example.com", "SOA", "NOERROR", true, false,
			rr("example.com", "SOA", soa),
		))
		put(m, "example.com", "NS", ip, false, resp(ip, "example.com", "NS", "NOERROR", true, false,
			rr("example.com", "NS", "ns1.example.net."),
			rr("example.com", "NS", "ns2.example.net."),
		))
	}
	put(m, "com", "DS", "8.8.8.8", true, resp("8.8.8.8", "com", "DS", "NOERROR", false, true,
		rr("com", "DS", "19718 13 2 ABCDEF"),
	))
	put(m, "example.com", "DS", "8.8.8.8", true, resp("8.8.8.8", "example.com", "DS", "NOERROR", false, true,
		rr("example.com", "DS", "12345 13 2 ABCDEF"),
	))
	put(m, "example.com", "DNSKEY", "8.8.8.8", true, resp("8.8.8.8", "example.com", "DNSKEY", "NOERROR", false, true,
		rr("example.com", "DNSKEY", "257 3 13 a2V5"),
		rr("example.com", "RRSIG", "DNSKEY 13 2 3600 1793538503 1793358503 12345 example.com. eHh4"),
	))
	return m
}

func labIn() LabInput {
	return LabInput{
		Name: "example.com", Type: "ALL", Server: "8.8.8.8", Timeout: time.Second,
		Resolvers: []Resolver{
			{IP: "8.8.8.8", Name: "Google"},
			{IP: "1.1.1.1", Name: "Cloudflare"},
		},
	}
}

func TestLabSignedAndConsistent(t *testing.T) {
	rep, err := RunLab(context.Background(), signedZone(), labIn())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Primary != "A" || rep.DNSSEC.CryptoValidation {
		t.Fatalf("report header %+v", rep)
	}
	if !strings.Contains(rep.Disclaimer, "not a validated signature") {
		t.Fatalf("disclaimer = %q", rep.Disclaimer)
	}
	if rep.DNSSEC.Level != "complete" || rep.DNSSEC.AD == nil || !*rep.DNSSEC.AD || !rep.DNSSEC.RRSIG {
		t.Fatalf("dnssec = %+v", rep.DNSSEC)
	}
	if rep.Nameservers.Serials.Code != "synced" || rep.Nameservers.Delegation.Code != "match" {
		t.Fatalf("ns serials=%+v delegation=%+v", rep.Nameservers.Serials, rep.Nameservers.Delegation)
	}
	if rep.Nameservers.SOA == nil || rep.Nameservers.SOA.Serial != 202 || rep.Nameservers.SOA.RName != "hostmaster@example.com" {
		t.Fatalf("soa = %+v", rep.Nameservers.SOA)
	}
	var sawA bool
	for _, rr := range rep.Records {
		if rr.Type == "A" && rr.Data == "192.0.2.10" {
			sawA = true
		}
		if rr.Type == "RRSIG" {
			t.Fatal("RRSIG should stay out of the record table")
		}
	}
	if !sawA {
		t.Fatalf("records = %+v", rep.Records)
	}
	if rep.Propagation.Baseline != "authoritative" || rep.Propagation.Match != 2 {
		t.Fatalf("prop = %+v", rep.Propagation)
	}
	if len(rep.Propagation.Rows) != 3 || rep.Propagation.Rows[0].State != "reference" {
		t.Fatalf("rows = %+v", rep.Propagation.Rows)
	}
}

func TestLabSerialLagAndUnsigned(t *testing.T) {
	m := signedZone()
	lagSOA := "ns1.example.net. hostmaster.example.com. 100 7200 3600 1209600 300"
	put(m, "example.com", "SOA", "1.2.3.5", false, resp("1.2.3.5", "example.com", "SOA", "NOERROR", true, false,
		rr("example.com", "SOA", lagSOA),
	))
	// Drop the chain so the verdict is about serials, and force unsigned.
	delete(m.hit, labKey(Query{Name: "example.com", Type: "DNSKEY", Server: "8.8.8.8", RD: true}))
	delete(m.hit, labKey(Query{Name: "example.com", Type: "DS", Server: "8.8.8.8", RD: true}))
	delete(m.hit, labKey(Query{Name: "com", Type: "DS", Server: "8.8.8.8", RD: true}))
	// The A answer still carries an RRSIG, which must not turn "no DS / no DNSKEY" into complete.
	rep, err := RunLab(context.Background(), m, labIn())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Nameservers.Serials.Code != "lag" {
		t.Fatalf("serials = %+v", rep.Nameservers.Serials)
	}
	if rep.DNSSEC.Level != "unsigned" {
		t.Fatalf("level = %s", rep.DNSSEC.Level)
	}
}

func TestLabDelegationMismatchAndUnderscore(t *testing.T) {
	m := signedZone()
	put(m, "example.com", "NS", "1.2.3.4", false, resp("1.2.3.4", "example.com", "NS", "NOERROR", true, false,
		rr("example.com", "NS", "ns1.example.net."),
	))
	rep, err := RunLab(context.Background(), m, labIn())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Nameservers.Delegation.Code != "mismatch" || len(rep.Nameservers.Delegation.OnlyParent) != 1 {
		t.Fatalf("delegation = %+v", rep.Nameservers.Delegation)
	}

	bare, err := RunLab(context.Background(), memQR{}, LabInput{Name: "_dmarc.example.com", Type: "TXT", Server: "8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	if bare.Name != "_dmarc.example.com" || bare.DNSSEC.Level != "no-apex" || bare.DNSSEC.CryptoValidation {
		t.Fatalf("underscore report = %+v", bare.DNSSEC)
	}
}

func TestLabBrokenDNSSEC(t *testing.T) {
	m := signedZone()
	delete(m.hit, labKey(Query{Name: "example.com", Type: "DNSKEY", Server: "8.8.8.8", RD: true}))
	rep, err := RunLab(context.Background(), m, labIn())
	if err != nil {
		t.Fatal(err)
	}
	if rep.DNSSEC.Level != "broken" {
		t.Fatalf("level = %s (ds=%d keys=%d)", rep.DNSSEC.Level, rep.DNSSEC.ApexDS, rep.DNSSEC.DNSKEY)
	}
}

func TestLabUsesResolverBaselineWhenAuthorityIsSilent(t *testing.T) {
	m := memQR{hit: map[string]*Response{}, err: map[string]error{}}
	put(m, "example.com", "A", "8.8.8.8", true, resp("8.8.8.8", "example.com", "A", "NOERROR", false, true,
		rr("example.com", "A", "192.0.2.10"),
	))
	put(m, "example.com", "A", "1.1.1.1", true, resp("1.1.1.1", "example.com", "A", "NOERROR", false, true,
		rr("example.com", "A", "192.0.2.10"),
	))
	put(m, "example.com", "NS", "8.8.8.8", true, resp("8.8.8.8", "example.com", "NS", "NOERROR", false, false,
		rr("example.com", "NS", "ns1.example.net."),
	))
	put(m, "example.com", "SOA", "8.8.8.8", true, resp("8.8.8.8", "example.com", "SOA", "NOERROR", false, false,
		rr("example.com", "SOA", "ns1.example.net. host.example.com. 5 1 1 1 1"),
	))
	put(m, "ns1.example.net", "A", "8.8.8.8", true, resp("8.8.8.8", "ns1.example.net", "A", "NOERROR", false, false,
		rr("ns1.example.net", "A", "1.2.3.4"),
	))
	m.err[labKey(Query{Name: "example.com", Type: "A", Server: "1.2.3.4", RD: false})] = ErrTimeout
	m.err[labKey(Query{Name: "example.com", Type: "SOA", Server: "1.2.3.4", RD: false})] = ErrTimeout
	rep, err := RunLab(context.Background(), m, labIn())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Propagation.Baseline != "resolver" || rep.Propagation.Match != 1 || rep.Propagation.Rows[0].State != "baseline" {
		t.Fatalf("baseline=%s match=%d rows=%+v", rep.Propagation.Baseline, rep.Propagation.Match, rep.Propagation.Rows)
	}
	if rep.Nameservers.Serials.Code != "unreachable" || rep.Nameservers.SOA == nil || rep.Nameservers.SOA.Serial != 5 {
		t.Fatalf("serials=%+v soa=%+v", rep.Nameservers.Serials, rep.Nameservers.SOA)
	}
}

func TestLabRejectsPrivateServer(t *testing.T) {
	_, err := RunLab(context.Background(), memQR{}, LabInput{Name: "example.com", Server: "10.0.0.1"})
	if err != ErrPrivateServer {
		t.Fatalf("err = %v", err)
	}
}
