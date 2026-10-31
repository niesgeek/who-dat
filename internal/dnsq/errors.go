package dnsq

import "errors"

var (
	// ErrInvalidName means the input is not a DNS name, wildcard, or IP address.
	ErrInvalidName = errors.New("invalid dns name")
	// ErrInvalidType means the type is not one this service will query.
	ErrInvalidType = errors.New("invalid dns type")
	// ErrInvalidServer means the server value is not a hostname or IP we can dial.
	ErrInvalidServer = errors.New("invalid dns server")
	// ErrPrivateServer means the server address is loopback, private, or otherwise non-public.
	ErrPrivateServer = errors.New("dns server is not a public address")
	// ErrTimeout means the resolver did not answer before the deadline.
	ErrTimeout = errors.New("dns timeout")
	// ErrUpstream means the dial failed or the message could not be read.
	ErrUpstream = errors.New("dns upstream")
)
