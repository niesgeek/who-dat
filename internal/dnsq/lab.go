package dnsq

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

var recordOrder = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "PTR"}

// RunLab expands one name into records, a propagation matrix, a DNSSEC
// presence check, and an NS/SOA consistency report.
func RunLab(ctx context.Context, qr Querier, in LabInput) (*Report, error) {
	if qr == nil {
		return nil, ErrUpstream
	}
	started := time.Now()
	parsed, err := ParseName(in.Name)
	if err != nil {
		return nil, err
	}
	server := strings.TrimSpace(in.Server)
	if server == "" {
		server = "8.8.8.8"
	}
	if _, err := ValidateServer(server); err != nil {
		return nil, err
	}
	qtype := strings.ToUpper(strings.TrimSpace(in.Type))
	if qtype == "" {
		qtype = "ALL"
	}
	if parsed.Reverse && (qtype == "ALL" || qtype == "A" || qtype == "AAAA") {
		qtype = "PTR"
	}
	if qtype != "ALL" {
		if _, _, err := canonicalType(qtype); err != nil {
			return nil, err
		}
	}
	timeout := in.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if timeout > 4*time.Second {
		timeout = 4 * time.Second
	}
	resolvers := in.Resolvers
	if len(resolvers) == 0 {
		resolvers = PublicResolvers
	}

	probes := probeTypes(parsed, qtype)
	got := askAll(ctx, qr, probes, func(i int) Query {
		return Query{Name: parsed.Name, Type: probes[i], Server: server, DNSSEC: true, RD: true, Timeout: timeout}
	})
	byType := map[string]*Response{}
	for i, typ := range probes {
		byType[typ] = got[i]
	}

	show := probes
	if qtype != "ALL" {
		show = []string{qtype}
	}
	records := collectRecords(show, byType)

	primary := qtype
	if qtype == "ALL" {
		primary = "A"
		if parsed.Reverse {
			primary = "PTR"
		}
		for _, typ := range probes {
			if resp := byType[typ]; resp != nil && len(ofType(resp.Answer, typ)) > 0 {
				primary = typ
				break
			}
		}
	}

	apex, soaRec, _ := findSOA(byType["SOA"])
	parentNS := nsHosts(byType["NS"])
	if apex != "" && !strings.EqualFold(apex, parsed.Name) {
		nsAtApex := ask(ctx, qr, Query{Name: apex, Type: "NS", Server: server, DNSSEC: true, RD: true, Timeout: timeout})
		if hosts := nsHosts(nsAtApex); len(hosts) > 0 {
			parentNS = hosts
		}
	}
	if len(parentNS) > 8 {
		parentNS = parentNS[:8]
	}

	hosts := resolveHosts(ctx, qr, parentNS, server, timeout)

	var (
		tldDS  *Response
		dnskey *Response
		apexDS *Response
		leaf   *Response
		mu     sync.Mutex
	)
	secJobs := []func(){}
	if apex != "" {
		tld := apex[strings.LastIndex(apex, ".")+1:]
		secJobs = append(secJobs,
			func() {
				r, err := askErr(ctx, qr, Query{Name: tld, Type: "DS", Server: server, DNSSEC: true, RD: true, Timeout: timeout})
				mu.Lock()
				defer mu.Unlock()
				tldDS = r
				_ = err
			},
			func() {
				r, err := askErr(ctx, qr, Query{Name: apex, Type: "DNSKEY", Server: server, DNSSEC: true, RD: true, Timeout: timeout})
				mu.Lock()
				defer mu.Unlock()
				dnskey = r
				_ = err
			},
			func() {
				r, err := askErr(ctx, qr, Query{Name: apex, Type: "DS", Server: server, DNSSEC: true, RD: true, Timeout: timeout})
				mu.Lock()
				defer mu.Unlock()
				apexDS = r
				_ = err
			},
		)
		if !strings.EqualFold(parsed.Name, apex) {
			secJobs = append(secJobs, func() {
				r, _ := askErr(ctx, qr, Query{Name: parsed.Name, Type: primary, Server: server, DNSSEC: true, RD: true, Timeout: timeout})
				mu.Lock()
				leaf = r
				mu.Unlock()
			})
		}
	}
	runJobs(ctx, 8, secJobs)

	authPrimary := make([]*Response, len(hosts))
	authSOA := make([]*Response, len(hosts))
	authNS := make([]*Response, len(hosts))
	authErr := make([]string, len(hosts))
	soaErr := make([]string, len(hosts))
	var jobs []func()
	for i := range hosts {
		if hosts[i].ip == "" {
			continue
		}
		i := i
		target := hosts[i].ip
		jobs = append(jobs, func() {
			r, err := askErr(ctx, qr, Query{Name: parsed.Name, Type: primary, Server: target, DNSSEC: true, RD: false, Timeout: timeout})
			authPrimary[i] = r
			authErr[i] = errClass(err)
		}, func() {
			zone := apex
			if zone == "" {
				zone = parsed.Name
			}
			r, err := askErr(ctx, qr, Query{Name: zone, Type: "SOA", Server: target, DNSSEC: false, RD: false, Timeout: timeout})
			authSOA[i] = r
			soaErr[i] = errClass(err)
		}, func() {
			zone := apex
			if zone == "" {
				zone = parsed.Name
			}
			r, _ := askErr(ctx, qr, Query{Name: zone, Type: "NS", Server: target, DNSSEC: false, RD: false, Timeout: timeout})
			authNS[i] = r
		})
	}
	resRows := make([]PropRow, len(resolvers))
	for i := range resolvers {
		i := i
		jobs = append(jobs, func() {
			r := resolvers[i]
			resp, err := askErr(ctx, qr, Query{Name: parsed.Name, Type: primary, Server: r.IP, DNSSEC: true, RD: true, Timeout: timeout})
			resRows[i] = propFromResolver(r, primary, resp, err)
		})
	}
	runJobs(ctx, 8, jobs)

	base, baseHost, baseNote := pickBaseline(hosts, authPrimary, primary)
	baseVals := []string{}
	hasBase := false
	baselineKind := "none"
	if base != nil {
		baseVals = valuesOf(base.Answer, primary)
		hasBase = base.Rcode == "NOERROR" || base.Rcode == "NXDOMAIN"
		if hasBase {
			baselineKind = "authoritative"
		}
	}
	if !hasBase {
		for i := range resRows {
			if resRows[i].State != "answered" {
				continue
			}
			baseVals = resRows[i].Values
			hasBase = true
			baselineKind = "resolver"
			resRows[i].State = "baseline"
			if resRows[i].Note == "" {
				resRows[i].Note = "recursive baseline; authoritative servers did not answer"
			}
			break
		}
	}
	rows := make([]PropRow, 0, 1+len(resRows))
	if base != nil && baselineKind == "authoritative" {
		rows = append(rows, PropRow{
			Role: "authoritative", Name: baseHost.name, Server: baseHost.ip, Note: baseNote,
			ElapsedMS: base.ElapsedMS, Rcode: base.Rcode, AA: base.Flags.AA,
			Answer: brief(baseVals), Values: baseVals, State: "reference",
		})
	}
	match, comparable := 0, 0
	resolverAD := false
	for i := range resRows {
		row := resRows[i]
		if row.State == "" {
			row.State = "down"
		}
		if row.State == "answered" {
			comparable++
			if !hasBase {
				row.State = "no-baseline"
			} else {
				row.State = compareVals(baseVals, row.Values)
				if row.State == "match" || row.State == "partial" {
					match++
				}
			}
		}
		if row.Values == nil {
			row.Values = []string{}
		}
		if row.Rcode != "" && row.AD {
			resolverAD = true
		}
		rows = append(rows, row)
	}
	if rows == nil {
		rows = []PropRow{}
	}
	baseline := baselineKind

	servers := make([]NSServer, len(hosts))
	serialRows := make([]serialRow, len(hosts))
	var shownSOA *SOA
	for i, h := range hosts {
		item := NSServer{Host: h.host, IP: h.ip, Error: h.err}
		if h.ip == "" && item.Error == "" {
			item.Error = "no-address"
		}
		if authSOA[i] != nil {
			item.ElapsedMS = authSOA[i].ElapsedMS
			item.Rcode = authSOA[i].Rcode
			item.AA = authSOA[i].Flags.AA
			if owner, parsedSOA, ok := findSOA(authSOA[i]); ok {
				_ = owner
				cp := parsedSOA
				item.SOA = &cp
				item.MName = parsedSOA.MName
				serial := parsedSOA.Serial
				item.Serial = &serial
				if shownSOA == nil {
					shownSOA = &cp
				}
			}
		} else if soaErr[i] != "" {
			item.Error = soaErr[i]
		}
		servers[i] = item
		serialRows[i] = serialRow{Host: h.host, Serial: item.Serial, MName: item.MName, Err: item.Error}
	}
	if shownSOA == nil && soaRec.MName != "" {
		cp := soaRec
		shownSOA = &cp
	}
	serials := judgeSerials(serialRows)

	var child []string
	childKnown := false
	for i, h := range hosts {
		if authSOA[i] == nil || !authSOA[i].Flags.AA || servers[i].Serial == nil {
			continue
		}
		if authNS[i] == nil {
			continue
		}
		child = nsHosts(authNS[i])
		childKnown = true
		_ = h
		break
	}
	deleg := judgeDelegation(parentNS, child, childKnown)
	var glue []string
	for _, h := range hosts {
		if inBailiwick(h.host, apex) && h.ip == "" {
			glue = append(glue, h.host)
		}
	}
	if glue == nil {
		glue = []string{}
	}
	deleg.GlueMissing = glue

	facts := dnssecFacts{ApexKnown: apex != ""}
	if dnskey != nil {
		facts.DNSKEYQueryOK = true
		facts.DNSKEY, facts.KSK = kskCount(dnskey.Answer)
		if hasRRSIG(dnskey.Answer, "DNSKEY") {
			facts.HasRRSIG = true
		}
	}
	if apexDS != nil {
		facts.DSQueryOK = true
		facts.ApexDS = len(ofType(apexDS.Answer, "DS"))
	}
	if tldDS != nil {
		facts.TLDQueryOK = true
		facts.TLDDS = len(ofType(tldDS.Answer, "DS"))
	}
	if leaf != nil && hasRRSIG(leaf.Answer, "") {
		facts.HasRRSIG = true
	}
	if resp := byType[primary]; resp != nil && hasRRSIG(resp.Answer, "") {
		facts.HasRRSIG = true
	}
	facts.AD = adBit(append([]*Response{dnskey, apexDS, leaf, byType[primary]}, authPrimary...)...)
	if resolverAD {
		on := true
		facts.AD = &on
	}

	level := judgeDNSSEC(facts)
	if records == nil {
		records = []RR{}
	}
	return &Report{
		OK:        true,
		Name:      parsed.Name,
		Display:   parsed.Display,
		Type:      qtype,
		Primary:   primary,
		Server:    server,
		ElapsedMS: time.Since(started).Milliseconds(),
		Records:   records,
		Propagation: Propagation{
			QType: primary, Baseline: baseline, Rows: rows, Match: match, Comparable: comparable,
		},
		DNSSEC: DNSSEC{
			Level: level, CryptoValidation: false, AD: facts.AD, Apex: apex,
			ApexDS: facts.ApexDS, TLDDS: facts.TLDDS, DNSKEY: facts.DNSKEY, KSK: facts.KSK,
			RRSIG: facts.HasRRSIG, TLDQueryOK: facts.TLDQueryOK, DNSKEYQueryOK: facts.DNSKEYQueryOK,
			DSQueryOK: facts.DSQueryOK, Disclaimer: PresenceDisclaimer,
		},
		Nameservers: Nameservers{
			Apex: apex, Servers: servers, SOA: shownSOA, Serials: serials, Delegation: deleg,
		},
		Disclaimer: PresenceDisclaimer,
	}, nil
}

type hostIP struct {
	host string
	ip   string
	err  string
}

type baseHost struct {
	name string
	ip   string
}

func probeTypes(parsed ParsedName, qtype string) []string {
	if qtype == "ALL" {
		out := []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV"}
		if parsed.Reverse {
			out = append(out, "PTR")
		}
		return out
	}
	out := []string{qtype}
	if qtype != "SOA" {
		out = append(out, "SOA")
	}
	if qtype != "NS" {
		out = append(out, "NS")
	}
	return out
}

func collectRecords(types []string, byType map[string]*Response) []RR {
	seen := map[string]struct{}{}
	var out []RR
	for _, typ := range types {
		resp := byType[typ]
		if resp == nil {
			continue
		}
		for _, rr := range ofType(resp.Answer, typ) {
			key := rr.Type + "|" + strings.ToLower(rr.Name) + "|" + strings.ToLower(rr.Data)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, rr)
		}
	}
	return out
}

func resolveHosts(ctx context.Context, qr Querier, names []string, server string, timeout time.Duration) []hostIP {
	out := make([]hostIP, len(names))
	var jobs []func()
	for i, name := range names {
		i, name := i, name
		jobs = append(jobs, func() {
			item := hostIP{host: name}
			a, err := askErr(ctx, qr, Query{Name: name, Type: "A", Server: server, DNSSEC: false, RD: true, Timeout: timeout})
			if err != nil {
				item.err = errClass(err)
			}
			if a != nil {
				if vals := valuesOf(a.Answer, "A"); len(vals) > 0 {
					item.ip = vals[0]
				}
			}
			if item.ip == "" {
				aaaa, err6 := askErr(ctx, qr, Query{Name: name, Type: "AAAA", Server: server, DNSSEC: false, RD: true, Timeout: timeout})
				if item.err == "" && err6 != nil {
					item.err = errClass(err6)
				}
				if aaaa != nil {
					if vals := valuesOf(aaaa.Answer, "AAAA"); len(vals) > 0 {
						item.ip = vals[0]
						item.err = ""
					}
				}
			}
			out[i] = item
		})
	}
	runJobs(ctx, 8, jobs)
	return out
}

func pickBaseline(hosts []hostIP, answers []*Response, qtype string) (*Response, baseHost, string) {
	for i, resp := range answers {
		if resp == nil || !resp.Flags.AA {
			continue
		}
		if resp.Rcode != "NOERROR" && resp.Rcode != "NXDOMAIN" {
			continue
		}
		return resp, baseHost{name: hosts[i].host, ip: hosts[i].ip}, "rd=0"
	}
	for i, resp := range answers {
		if resp == nil {
			continue
		}
		return resp, baseHost{name: hosts[i].host, ip: hosts[i].ip}, "rd=0"
	}
	_ = qtype
	return nil, baseHost{}, ""
}

func propFromResolver(r Resolver, qtype string, resp *Response, err error) PropRow {
	row := PropRow{
		Role: "resolver", Name: r.Name, Server: r.IP, Note: r.Note,
		Values: []string{},
	}
	if err != nil || resp == nil {
		row.State = "down"
		row.Error = errClass(err)
		if row.Error == "" {
			row.Error = "upstream"
		}
		return row
	}
	row.ElapsedMS = resp.ElapsedMS
	row.Rcode = resp.Rcode
	row.AA = resp.Flags.AA
	row.AD = resp.Flags.AD
	vals := valuesOf(resp.Answer, qtype)
	row.Values = vals
	row.Answer = brief(vals)
	if resp.Rcode == "NOERROR" || resp.Rcode == "NXDOMAIN" {
		row.State = "answered"
		return row
	}
	row.State = "fail"
	return row
}

func askAll(ctx context.Context, qr Querier, keys []string, build func(i int) Query) []*Response {
	out := make([]*Response, len(keys))
	var jobs []func()
	for i := range keys {
		i := i
		jobs = append(jobs, func() {
			out[i] = ask(ctx, qr, build(i))
		})
	}
	runJobs(ctx, 8, jobs)
	return out
}

func ask(ctx context.Context, qr Querier, q Query) *Response {
	resp, err := askErr(ctx, qr, q)
	if err != nil {
		return nil
	}
	return resp
}

func askErr(ctx context.Context, qr Querier, q Query) (*Response, error) {
	qctx, cancel := context.WithTimeout(ctx, q.Timeout)
	defer cancel()
	return qr.Query(qctx, q)
}

func errClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrTimeout), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout"
	case errors.Is(err, ErrPrivateServer):
		return "private"
	case errors.Is(err, ErrInvalidServer), errors.Is(err, ErrInvalidName):
		return "invalid-server"
	default:
		return "upstream"
	}
}

func runJobs(ctx context.Context, limit int, jobs []func()) {
	if len(jobs) == 0 {
		return
	}
	if limit < 1 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for _, job := range jobs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(job func()) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
				job()
			}
		}(job)
	}
	wg.Wait()
}
