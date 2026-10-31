package dnsq

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Querier sends one DNS query. *Client implements it; tests supply a fake.
type Querier interface {
	Query(ctx context.Context, q Query) (*Response, error)
}

// ResolveFunc looks up a hostname used as a DNS server address.
type ResolveFunc func(ctx context.Context, host string) ([]net.IP, error)

type exchanger func(ctx context.Context, network string, msg *dns.Msg, addr string, timeout time.Duration) (*dns.Msg, time.Duration, error)

// Client dials DNS servers over UDP and falls back to TCP when the UDP
// answer is truncated or the UDP socket fails for a reason other than timeout.
type Client struct {
	Timeout  time.Duration
	Resolve  ResolveFunc
	exchange exchanger
	now      func() time.Time
}

// New returns a client. timeout is the default per-query budget; <= 0 uses 4s.
func New(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	return &Client{Timeout: timeout, now: time.Now}
}

// Query sends one question. Server must be a public IP or a hostname that
// resolves to one. DNSSEC sets the EDNS DO bit. RD is passed through.
func (c *Client) Query(ctx context.Context, q Query) (*Response, error) {
	if c == nil {
		c = New(0)
	}
	parsed, err := ParseName(q.Name)
	if err != nil {
		return nil, err
	}
	typ, code, err := canonicalType(q.Type)
	if err != nil {
		return nil, err
	}
	server, err := c.resolveServer(ctx, q.Server)
	if err != nil {
		return nil, err
	}
	timeout := q.Timeout
	if timeout <= 0 {
		timeout = c.Timeout
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(parsed.Name), code)
	msg.RecursionDesired = q.RD
	if q.DNSSEC {
		msg.SetEdns0(1232, true)
	}
	addr := net.JoinHostPort(server, "53")
	started := c.clock()()

	resp, _, err := c.exchangeNet(ctx, "udp", msg.Copy(), addr, timeout)
	if err == nil && resp != nil && !resp.Truncated {
		return fromMsg(parsed.Name, typ, server, q.DNSSEC, resp, "udp", false, c.clock()().Sub(started).Milliseconds()), nil
	}
	if err != nil && (isTimeout(err) || ctx.Err() != nil) {
		return nil, ErrTimeout
	}
	trunc := err == nil && resp != nil && resp.Truncated
	resp, _, err = c.exchangeNet(ctx, "tcp", msg.Copy(), addr, timeout)
	if err != nil {
		if isTimeout(err) || ctx.Err() != nil {
			return nil, ErrTimeout
		}
		return nil, ErrUpstream
	}
	if resp == nil {
		return nil, ErrUpstream
	}
	return fromMsg(parsed.Name, typ, server, q.DNSSEC, resp, "tcp", trunc, c.clock()().Sub(started).Milliseconds()), nil
}

func (c *Client) clock() func() time.Time {
	if c != nil && c.now != nil {
		return c.now
	}
	return time.Now
}

func (c *Client) exchangeNet(ctx context.Context, network string, msg *dns.Msg, addr string, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	if c != nil && c.exchange != nil {
		return c.exchange(ctx, network, msg, addr, timeout)
	}
	client := &dns.Client{Net: network, Timeout: timeout}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return client.ExchangeContext(qctx, msg, addr)
}

func (c *Client) resolveServer(ctx context.Context, server string) (string, error) {
	host, err := ValidateServer(server)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	resolve := c.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	ips, err := resolve(rctx, host)
	if err != nil || len(ips) == 0 {
		return "", ErrInvalidServer
	}
	for _, ip := range ips {
		if isPublic(ip) {
			return ip.String(), nil
		}
	}
	return "", ErrPrivateServer
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
