// Package dnsq is the DNS laboratory client behind /api/dns and /dns.
//
// Queries go out from this process to public resolvers and to the domain's
// authoritative servers. DNSSEC results are a presence check (DS, DNSKEY,
// RRSIG, and the AD bit). This package does not validate signatures.
package dnsq
