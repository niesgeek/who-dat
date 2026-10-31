package dnsq

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResponseTextAndOPTSkip(t *testing.T) {
	a, err := dns.NewRR("example.com. 300 IN A 192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := dns.NewRR("example.com. 300 IN RRSIG A 13 2 300 1793538503 1793358503 34505 example.com. eHh4")
	if err != nil {
		t.Fatal(err)
	}
	msg := new(dns.Msg)
	msg.SetReply(&dns.Msg{MsgHdr: dns.MsgHdr{RecursionDesired: true}})
	msg.Authoritative = false
	msg.AuthenticatedData = true
	msg.RecursionAvailable = true
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{a, sig}
	msg.Extra = []dns.RR{&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}}}

	resp := fromMsg("example.com", "A", "8.8.8.8", true, msg, "tcp", false, 8)
	if len(resp.Additional) != 0 {
		t.Fatalf("OPT leaked into additional: %+v", resp.Additional)
	}
	if resp.Flags.AD != true || resp.Rcode != "NOERROR" || len(resp.Answer) != 2 {
		t.Fatalf("response = %+v", resp)
	}
	text := resp.Text()
	if !strings.HasPrefix(text, "# example.com @8.8.8.8 (tcp, 8ms, rcode=NOERROR, aa=0, ad=1)\n") {
		t.Fatalf("header = %q", text)
	}
	if !strings.Contains(text, "example.com.\t300\tIN\tA\t192.0.2.10\n") {
		t.Fatalf("missing A line: %s", text)
	}
	if !strings.Contains(text, "\tRRSIG\tA 13 2 300 ") {
		t.Fatalf("missing RRSIG rdata: %s", text)
	}
}

type scriptEx struct {
	nets []string
	udp  *dns.Msg
	udpE error
	tcp  *dns.Msg
	tcpE error
}

func (s *scriptEx) exchange(_ context.Context, network string, msg *dns.Msg, _ string, _ time.Duration) (*dns.Msg, time.Duration, error) {
	s.nets = append(s.nets, network)
	if network == "udp" {
		if s.udp != nil {
			s.udp.Id = msg.Id
		}
		return s.udp, time.Millisecond, s.udpE
	}
	if s.tcp != nil {
		s.tcp.Id = msg.Id
	}
	return s.tcp, time.Millisecond, s.tcpE
}

func TestUDPThenTCPOnTruncation(t *testing.T) {
	udp := &dns.Msg{}
	udp.Truncated = true
	udp.Rcode = dns.RcodeSuccess
	tcp := &dns.Msg{}
	tcp.Rcode = dns.RcodeSuccess
	tcp.Answer = []dns.RR{mustRR(t, "example.com. 30 IN A 192.0.2.1")}
	ex := &scriptEx{udp: udp, tcp: tcp}
	c := New(time.Second)
	c.exchange = ex.exchange
	resp, err := c.Query(context.Background(), Query{Name: "example.com", Type: "A", Server: "8.8.8.8", RD: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.FellBackFromTruncation || resp.Transport != "tcp" {
		t.Fatalf("fallback = %+v", resp)
	}
	if strings.Join(ex.nets, ",") != "udp,tcp" {
		t.Fatalf("nets = %v", ex.nets)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].Data != "192.0.2.1" {
		t.Fatalf("answer = %+v", resp.Answer)
	}
}

func TestUDPTimeoutDoesNotOpenTCP(t *testing.T) {
	ex := &scriptEx{udpE: context.DeadlineExceeded}
	c := New(time.Second)
	c.exchange = ex.exchange
	_, err := c.Query(context.Background(), Query{Name: "example.com", Type: "A", Server: "1.1.1.1", RD: true})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	if strings.Join(ex.nets, ",") != "udp" {
		t.Fatalf("nets = %v", ex.nets)
	}
}

func TestPrivateServerIsNotDialed(t *testing.T) {
	ex := &scriptEx{}
	c := New(time.Second)
	c.exchange = ex.exchange
	_, err := c.Query(context.Background(), Query{Name: "example.com", Type: "A", Server: "127.0.0.1"})
	if !errors.Is(err, ErrPrivateServer) {
		t.Fatalf("err = %v", err)
	}
	if len(ex.nets) != 0 {
		t.Fatalf("dialed %v", ex.nets)
	}
}

func TestHostnameResolvingToPrivateIsRejected(t *testing.T) {
	ex := &scriptEx{}
	c := New(time.Second)
	c.exchange = ex.exchange
	c.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.9.8.7")}, nil
	}
	_, err := c.Query(context.Background(), Query{Name: "example.com", Type: "A", Server: "inside.example"})
	if !errors.Is(err, ErrPrivateServer) {
		t.Fatalf("err = %v", err)
	}
	if len(ex.nets) != 0 {
		t.Fatal("dialed private address")
	}
}

func TestRejectsAnyAndAXFR(t *testing.T) {
	c := New(time.Second)
	c.exchange = (&scriptEx{}).exchange
	for _, typ := range []string{"ANY", "AXFR", ""} {
		_, err := c.Query(context.Background(), Query{Name: "example.com", Type: typ, Server: "8.8.8.8"})
		if !errors.Is(err, ErrInvalidType) {
			t.Errorf("type %q err = %v", typ, err)
		}
	}
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
