package dnsq

import "time"

// Resolver is one public recursive resolver in the propagation matrix.
type Resolver struct {
	IP   string
	Name string
	Note string
}

// PublicResolvers are the recursive servers the laboratory asks with RD=1.
// Cloudflare is included because this process can dial 1.1.1.1.
var PublicResolvers = []Resolver{
	{IP: "8.8.8.8", Name: "Google", Note: "anycast"},
	{IP: "1.1.1.1", Name: "Cloudflare", Note: "anycast"},
	{IP: "9.9.9.9", Name: "Quad9", Note: "filters malware"},
	{IP: "208.67.222.222", Name: "OpenDNS", Note: "anycast"},
	{IP: "223.5.5.5", Name: "AliDNS", Note: "CN"},
	{IP: "119.29.29.29", Name: "DNSPod", Note: "CN"},
}

// SOA is a parsed start of authority.
type SOA struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

// PropRow is one cell of the propagation matrix.
type PropRow struct {
	Role      string   `json:"role"`
	Name      string   `json:"name"`
	Server    string   `json:"server"`
	Note      string   `json:"note,omitempty"`
	ElapsedMS int64    `json:"elapsed_ms"`
	Rcode     string   `json:"rcode,omitempty"`
	AA        bool     `json:"aa"`
	Answer    string   `json:"answer"`
	Values    []string `json:"values"`
	AD        bool     `json:"ad"`
	State     string   `json:"state"`
	Error     string   `json:"error,omitempty"`
}

// Propagation is the matrix for one qtype.
type Propagation struct {
	QType      string    `json:"qtype"`
	Baseline   string    `json:"baseline"`
	Rows       []PropRow `json:"rows"`
	Match      int       `json:"match"`
	Comparable int       `json:"comparable"`
}

// DNSSEC is a presence check, not a cryptographic validation.
type DNSSEC struct {
	Level            string `json:"level"`
	CryptoValidation bool   `json:"cryptoValidation"`
	AD               *bool  `json:"ad"`
	Apex             string `json:"apex,omitempty"`
	ApexDS           int    `json:"apexDs"`
	TLDDS            int    `json:"tldDs"`
	DNSKEY           int    `json:"dnskey"`
	KSK              int    `json:"ksk"`
	RRSIG            bool   `json:"rrsig"`
	TLDQueryOK       bool   `json:"tldQueryOk"`
	DNSKEYQueryOK    bool   `json:"dnskeyQueryOk"`
	DSQueryOK        bool   `json:"dsQueryOk"`
	Disclaimer       string `json:"disclaimer"`
}

// NSServer is one authoritative nameserver and the SOA it returned.
type NSServer struct {
	Host      string  `json:"host"`
	IP        string  `json:"ip,omitempty"`
	Serial    *uint32 `json:"serial"`
	AA        bool    `json:"aa"`
	ElapsedMS int64   `json:"elapsed_ms"`
	Rcode     string  `json:"rcode,omitempty"`
	MName     string  `json:"mname,omitempty"`
	Error     string  `json:"error,omitempty"`
	SOA       *SOA    `json:"soa,omitempty"`
}

// SerialGroup is one primary-nameserver family and its newest serial.
type SerialGroup struct {
	MName  string   `json:"mname"`
	Serial int64    `json:"serial"`
	Hosts  []string `json:"hosts"`
}

// Serials summarizes whether authoritative servers share a serial.
type Serials struct {
	Code    string        `json:"code"`
	Latest  int64         `json:"latest"`
	Lagging []string      `json:"lagging"`
	Groups  []SerialGroup `json:"groups"`
}

// Delegation compares parent NS names with the child zone's own NS names.
type Delegation struct {
	Parent      []string `json:"parent"`
	Child       []string `json:"child"`
	ChildKnown  bool     `json:"childKnown"`
	Consistent  bool     `json:"consistent"`
	OnlyParent  []string `json:"onlyParent"`
	OnlyChild   []string `json:"onlyChild"`
	GlueMissing []string `json:"glueMissing"`
	Code        string   `json:"code"`
}

// Nameservers is the NS and SOA panel.
type Nameservers struct {
	Apex       string     `json:"apex,omitempty"`
	Servers    []NSServer `json:"servers"`
	SOA        *SOA       `json:"soa,omitempty"`
	Serials    Serials    `json:"serials"`
	Delegation Delegation `json:"delegation"`
}

// Report is the JSON body of GET /api/dns/lab.
type Report struct {
	OK          bool        `json:"ok"`
	Name        string      `json:"name"`
	Display     string      `json:"display"`
	Type        string      `json:"type"`
	Primary     string      `json:"primary"`
	Server      string      `json:"server"`
	ElapsedMS   int64       `json:"elapsed_ms"`
	Records     []RR        `json:"records"`
	Propagation Propagation `json:"propagation"`
	DNSSEC      DNSSEC      `json:"dnssec"`
	Nameservers Nameservers `json:"nameservers"`
	Path        Path        `json:"path"`
	Disclaimer  string      `json:"disclaimer"`
}

// LabInput selects what the laboratory expands.
type LabInput struct {
	Name      string
	Type      string
	Server    string
	Timeout   time.Duration // per-probe budget; 0 uses 2s
	Resolvers []Resolver
	Client    ClientHint
}
