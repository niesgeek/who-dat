package whois

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	whoisparser "github.com/likexian/whois-parser"

	"github.com/lissy93/who-dat/internal/domain"
	"github.com/lissy93/who-dat/internal/model"
	"github.com/lissy93/who-dat/internal/srcerr"
)

const rawContentType = "text/plain; charset=utf-8"

// mapWhois parses raw WHOIS text and maps it to the canonical model. A "not found" parse
// result is a successful "not registered" answer, not an error.
func mapWhois(n domain.Name, raw string) (*model.Result, error) {
	r := model.New(n.ASCII, n.ASCII, n.TLD)
	r.Meta = model.Meta{Source: model.SourceWhois, FetchedAt: time.Now().UTC(), Bytes: len(raw)}
	r.Raw = []byte(raw)
	r.RawContentType = rawContentType
	if n.IsIDN() {
		r.DomainUnicode = model.Str(n.Unicode)
	}

	info, err := whoisparser.Parse(raw)
	if err != nil {
		switch {
		case errors.Is(err, whoisparser.ErrNotFoundDomain),
			errors.Is(err, whoisparser.ErrReservedDomain),
			errors.Is(err, whoisparser.ErrPremiumDomain),
			errors.Is(err, whoisparser.ErrBlockedDomain):
			r.IsRegistered = false
			return r, nil
		case errors.Is(err, whoisparser.ErrDomainLimitExceed):
			return nil, &srcerr.RateLimited{Err: err}
		default:
			return nil, fmt.Errorf("%w: whois parse: %v", srcerr.ErrUpstream, err)
		}
	}

	r.IsRegistered = true
	mapDomain(r, info.Domain)
	mapRegistrar(r, info.Registrar)
	r.Contacts.Registrant = contact(info.Registrant)
	r.Contacts.Admin = contact(info.Administrative)
	r.Contacts.Tech = contact(info.Technical)
	r.Contacts.Billing = contact(info.Billing)
	// The parser's date layouts do not cover every registry's format (see
	// fillMissingDates): when it leaves a date empty, read the line ourselves
	// instead of showing a blank, then rebuild the timeline from the filled
	// dates.
	fillMissingDates(r, raw)
	r.Events = synthesizeEvents(r.Dates)
	return r, nil
}

// fallbackDateLabels maps each date role to the WHOIS labels a registry may
// use for it, longest label first so "Created On:" wins over "Created:".
var fallbackDateLabels = []struct {
	role   string
	labels []string
}{
	{"created", []string{"Created On:", "Creation Date:", "Created:"}},
	{"updated", []string{"Last Updated On:", "Updated Date:", "Last Updated:", "Updated:"}},
	{"expires", []string{"Expiration Date:", "Expiry Date:", "Expire Date:", "Expires:"}},
}

// fallbackDateLayouts are tried for a fallback date value. The parser already
// handles the common shapes; this list only adds the ones it misses, notably
// "10-Oct-2022 06:55:49 UTC" (whois.pp.ua) whose trailing zone name matches
// none of its layouts. time.Parse treats a layout's MST slot as a zone
// abbreviation, so "UTC" lands in UTC.
var fallbackDateLayouts = []string{
	"02-Jan-2006 15:04:05 MST",
	"02 Jan 2006 15:04:05 MST",
	"02-Jan-2006 15:04:05",
	"02-Jan-2006",
	"2006-01-02 15:04:05 MST",
	"2006-01-02 15:04:05",
	"2006-01-02",
	time.RFC3339,
}

// fillMissingDates fills any date the parser left empty by scanning the raw
// text for that role's labels. It never overwrites a date the parser did find.
func fillMissingDates(r *model.Result, raw string) {
	missing := map[string]bool{
		"created": r.Dates.Created == nil,
		"updated": r.Dates.Updated == nil,
		"expires": r.Dates.Expires == nil,
	}
	if !missing["created"] && !missing["updated"] && !missing["expires"] {
		return
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		for _, entry := range fallbackDateLabels {
			if !missing[entry.role] {
				continue
			}
			for _, label := range entry.labels {
				if !strings.HasPrefix(line, label) {
					continue
				}
				value := strings.TrimSpace(strings.TrimPrefix(line, label))
				if value == "" {
					break
				}
				for _, layout := range fallbackDateLayouts {
					if t, err := time.Parse(layout, value); err == nil {
						switch entry.role {
						case "created":
							r.Dates.Created = model.Time(t.UTC())
						case "updated":
							r.Dates.Updated = model.Time(t.UTC())
						case "expires":
							r.Dates.Expires = model.Time(t.UTC())
						}
						missing[entry.role] = false
						break
					}
				}
				break
			}
		}
	}
}

func mapDomain(r *model.Result, d *whoisparser.Domain) {
	if d == nil {
		return
	}
	r.ID = model.Str(d.ID)
	r.Status = model.NormalizeStatuses(d.Status)
	r.DNSSEC.Signed = d.DNSSec
	r.Dates.Created = timePtr(d.CreatedDateInTime)
	r.Dates.Updated = timePtr(d.UpdatedDateInTime)
	r.Dates.Expires = timePtr(d.ExpirationDateInTime)
	r.Registrar.WhoisServer = model.Str(d.WhoisServer)
	if d.WhoisServer != "" {
		r.Meta.Server = model.Str(d.WhoisServer)
	}
	for _, ns := range d.NameServers {
		r.Nameservers = append(r.Nameservers, model.Nameserver{
			Name: ns,
			IPv4: []string{},
			IPv6: []string{},
		})
	}
	// WHOIS text has no event list, so synthesize the same timeline shape
	// RDAP returns from the three parsed dates.
	r.Events = synthesizeEvents(r.Dates)
}

// synthesizeEvents builds a chronological event list from parsed WHOIS dates.
func synthesizeEvents(d model.Dates) []model.Event {
	events := []model.Event{}
	if d.Created != nil {
		events = append(events, model.Event{Action: "registration", Date: d.Created})
	}
	if d.Updated != nil {
		events = append(events, model.Event{Action: "last changed", Date: d.Updated})
	}
	if d.Expires != nil {
		events = append(events, model.Event{Action: "expiration", Date: d.Expires})
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Date.Before(*events[j].Date) })
	return events
}

// timePtr converts a whois-parser nullable time to the model's UTC pointer form.
func timePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	return model.Time(*t)
}

func mapRegistrar(r *model.Result, c *whoisparser.Contact) {
	if c == nil {
		return
	}
	name := c.Name
	if name == "" {
		name = c.Organization
	}
	r.Registrar.Name = model.Str(name)
	r.Registrar.URL = model.Str(c.ReferralURL)
	r.Registrar.AbuseEmail = model.Str(c.Email)
	r.Registrar.AbusePhone = model.Str(c.Phone)
}

func contact(c *whoisparser.Contact) model.Contact {
	if c == nil {
		return model.Contact{Redacted: true}
	}
	out := model.Contact{
		Name:         model.Str(c.Name),
		Organization: model.Str(c.Organization),
		Email:        model.Str(c.Email),
		Phone:        model.Str(c.Phone),
		Address: model.Address{
			Street:     model.Str(c.Street),
			City:       model.Str(c.City),
			State:      model.Str(c.Province),
			PostalCode: model.Str(c.PostalCode),
			Country:    model.Str(c.Country),
		},
	}
	out.Redacted = out.Name == nil && out.Organization == nil && out.Email == nil && out.Phone == nil
	return out
}
