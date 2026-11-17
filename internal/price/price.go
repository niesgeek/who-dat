// Package price fetches per-suffix registration, renewal and transfer prices
// from the public nazhumi.com price-comparison API (no key, public read-only
// GET endpoints) and reduces each suffix to the cheapest registrar per
// order. Prices are a snapshot taken by the upstream collector, not a live
// quote: every quote carries its registrar, its collection time, and the
// source link, and the final price is always the registrar's checkout page.
package price

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
)

// DefaultBase is the public nazhumi API root.
const DefaultBase = "https://www.nazhumi.com/api/v1"

// DefaultTTL is how long one suffix's cheapest quotes are cached. The upstream
// guide suggests caching a query for about five minutes.
const DefaultTTL = 5 * time.Minute

// Orders are the three price kinds, in display order.
var Orders = []string{"register", "renew", "transfer"}

// Promo is one coupon for a cheapest quote, from the promo-detail query.
type Promo struct {
	Code     string   `json:"code"`
	PriceCNY *float64 `json:"priceCny,omitempty"`
	Limit    int      `json:"limit,omitempty"`
	NewUser  bool     `json:"newUser,omitempty"`
	End      string   `json:"end,omitempty"`
}

// Quote is the cheapest registrar for one order. Empty is true when the
// upstream lists no usable price for that order.
type Quote struct {
	Order         string   `json:"order"`
	Empty         bool     `json:"empty"`
	StandardCNY   *float64 `json:"standardCny,omitempty"`
	OrigValue     *float64 `json:"origValue,omitempty"`
	Currency      string   `json:"currency,omitempty"`
	EffectiveCNY  *float64 `json:"effectiveCny,omitempty"`
	RegistrarCode string   `json:"registrarCode,omitempty"`
	RegistrarName string   `json:"registrarName,omitempty"`
	RegistrarWeb  string   `json:"registrarWeb,omitempty"`
	Promo         *Promo   `json:"promo,omitempty"`
	UpdatedTime   string   `json:"updatedtime,omitempty"`
}

// Response is the cheapest-per-order summary for one suffix.
type Response struct {
	OK        bool      `json:"ok"`
	TLD       string    `json:"tld"`
	Source    string    `json:"source"`
	SourceURL string    `json:"sourceUrl"`
	FetchedAt time.Time `json:"fetchedAt"`
	Updated   string    `json:"updated,omitempty"`
	Total     int       `json:"total"`
	Items     []Quote   `json:"items"`
}

// numOrNA decodes a price that is either a number or the string "n/a".
type numOrNA struct {
	V *float64
}

func (n *numOrNA) UnmarshalJSON(b []byte) error {
	if string(b) == `"n/a"` || string(b) == "null" {
		n.V = nil
		return nil
	}
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	n.V = &f
	return nil
}

type listRow struct {
	Registrar     string  `json:"registrar"`
	RegistrarName string  `json:"registrarname"`
	RegistrarWeb  string  `json:"registrarweb"`
	Currency      string  `json:"currency"`
	Register      numOrNA `json:"register"`
	RegisterCNY   numOrNA `json:"register_cny"`
	RegisterEff   numOrNA `json:"register_eff_cny"`
	Renew         numOrNA `json:"renew"`
	RenewCNY      numOrNA `json:"renew_cny"`
	RenewEff      numOrNA `json:"renew_eff_cny"`
	Transfer      numOrNA `json:"transfer"`
	TransferCNY   numOrNA `json:"transfer_cny"`
	TransferEff   numOrNA `json:"transfer_eff_cny"`
	PromoCode     struct {
		Register bool `json:"register"`
		Renew    bool `json:"renew"`
		Transfer bool `json:"transfer"`
	} `json:"promocode"`
	UpdatedTime string `json:"updatedtime"`
}

type listResponse struct {
	Code int `json:"code"`
	Data struct {
		Domain string    `json:"domain"`
		Total  int       `json:"total"`
		Count  int       `json:"count"`
		Price  []listRow `json:"price"`
	} `json:"data"`
}

type promoDetail struct {
	Code int `json:"code"`
	Data struct {
		PromoCode bool `json:"promocode"`
		Promos    []struct {
			Code        string  `json:"code"`
			PriceCNY    numOrNA `json:"price_cny"`
			LimitCount  int     `json:"limit_count"`
			NewUserOnly bool    `json:"new_user_only"`
			EndTime     string  `json:"endtime"`
		} `json:"promos"`
	} `json:"data"`
}

// ValidSuffix reports whether s looks like a domain suffix (one or more
// labels, e.g. "com" or "co.uk"). It accepts Unicode suffixes via punycode.
func ValidSuffix(s string) bool {
	s = strings.TrimPrefix(strings.TrimSpace(s), ".")
	if s == "" || len(s) > 253 || strings.ContainsAny(s, "/?#:@") {
		return false
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return false
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

type cacheEntry struct {
	res       *Response
	expiresAt time.Time
}

// Service fetches cheapest-per-order quotes with a short TTL cache.
type Service struct {
	http *http.Client
	base string
	ttl  time.Duration

	mu      sync.Mutex
	entries map[string]cacheEntry
}

// New returns a Service using the public API root.
func New(httpClient *http.Client) *Service {
	return NewWithBase(httpClient, DefaultBase, DefaultTTL)
}

// NewWithBase returns a Service pointed at base (for tests) with ttl caching.
func NewWithBase(httpClient *http.Client, base string, ttl time.Duration) *Service {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Service{http: httpClient, base: strings.TrimRight(base, "/"), ttl: ttl, entries: make(map[string]cacheEntry)}
}

// Cheapest returns the cheapest registrar per order for tld, from cache when fresh.
func (s *Service) Cheapest(ctx context.Context, tld string) (*Response, error) {
	tld = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(tld), "."))
	if !ValidSuffix(tld) {
		return nil, fmt.Errorf("invalid suffix %q", tld)
	}

	s.mu.Lock()
	if e, ok := s.entries[tld]; ok && time.Now().Before(e.expiresAt) {
		s.mu.Unlock()
		return e.res, nil
	}
	s.mu.Unlock()

	res, err := s.fetch(ctx, tld)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.entries[tld] = cacheEntry{res: res, expiresAt: time.Now().Add(s.ttl)}
	s.mu.Unlock()
	return res, nil
}

func (s *Service) fetch(ctx context.Context, tld string) (*Response, error) {
	rows, total, err := s.fetchList(ctx, tld)
	if err != nil {
		return nil, err
	}

	res := &Response{
		OK:        true,
		TLD:       tld,
		Source:    "nazhumi.com",
		SourceURL: "https://www.nazhumi.com/domain/" + tld,
		FetchedAt: time.Now().UTC(),
		Total:     total,
		Items:     make([]Quote, 0, len(Orders)),
	}
	for _, order := range Orders {
		res.Items = append(res.Items, s.cheapestFor(ctx, tld, order, rows))
	}
	// Updated is the newest collection time among the quoted rows.
	var latest string
	for _, q := range res.Items {
		if q.UpdatedTime > latest {
			latest = q.UpdatedTime
		}
	}
	res.Updated = latest
	return res, nil
}

// fetchList pulls the full registrar list for tld, paging at 100 rows until
// the upstream total is reached. One list call carries all three orders'
// prices, so no per-order list fetch is needed.
func (s *Service) fetchList(ctx context.Context, tld string) ([]listRow, int, error) {
	var rows []listRow
	total := -1
	for page := 1; page <= 10; page++ {
		u := s.base + "?domain=" + url.QueryEscape(tld) + "&order=register&limit=100&page=" + itoa(page)
		var lr listResponse
		if err := s.getJSON(ctx, u, &lr); err != nil {
			return nil, 0, err
		}
		if lr.Code != 100 {
			return nil, 0, fmt.Errorf("price upstream returned code %d", lr.Code)
		}
		if total < 0 {
			total = lr.Data.Total
		}
		rows = append(rows, lr.Data.Price...)
		if len(rows) >= total || lr.Data.Count == 0 {
			break
		}
	}
	if total < 0 {
		total = 0
	}
	return rows, total, nil
}

// cheapestFor picks the lowest effective-CNY row for order ("n/a" never wins)
// and, when that row carries a coupon, fetches its promo detail.
func (s *Service) cheapestFor(ctx context.Context, tld, order string, rows []listRow) Quote {
	q := Quote{Order: order, Empty: true}
	var best *listRow
	for i := range rows {
		eff := effFor(&rows[i], order)
		if eff == nil {
			continue
		}
		if best == nil || *eff < *effFor(best, order) {
			best = &rows[i]
		}
	}
	if best == nil {
		return q
	}
	q.Empty = false
	q.StandardCNY = cnyFor(best, order)
	q.OrigValue = origFor(best, order)
	q.Currency = best.Currency
	q.EffectiveCNY = effFor(best, order)
	q.RegistrarCode = best.Registrar
	q.RegistrarName = best.RegistrarName
	q.RegistrarWeb = best.RegistrarWeb
	q.UpdatedTime = best.UpdatedTime
	if hasPromo(best, order) {
		if p := s.fetchPromo(ctx, tld, order, best.Registrar); p != nil {
			q.Promo = p
		}
	}
	return q
}

// fetchPromo reads the promo detail for one registrar/suffix/order. It returns
// the cheapest promo (the detail list is already price-sorted). A failure here
// is not fatal: the quote is still shown without its coupon.
func (s *Service) fetchPromo(ctx context.Context, tld, order, registrar string) *Promo {
	u := s.base + "?registrar=" + url.QueryEscape(registrar) + "&domain=" + url.QueryEscape(tld) + "&order=" + url.QueryEscape(order)
	var pd promoDetail
	if err := s.getJSON(ctx, u, &pd); err != nil {
		return nil
	}
	if pd.Code != 100 || !pd.Data.PromoCode || len(pd.Data.Promos) == 0 {
		return nil
	}
	// Cheapest promo first; keep the original code case for copy/paste.
	promos := append([]struct {
		Code        string  `json:"code"`
		PriceCNY    numOrNA `json:"price_cny"`
		LimitCount  int     `json:"limit_count"`
		NewUserOnly bool    `json:"new_user_only"`
		EndTime     string  `json:"endtime"`
	}{}, pd.Data.Promos...)
	sort.Slice(promos, func(i, j int) bool {
		if promos[i].PriceCNY.V == nil {
			return false
		}
		if promos[j].PriceCNY.V == nil {
			return true
		}
		return *promos[i].PriceCNY.V < *promos[j].PriceCNY.V
	})
	p := promos[0]
	return &Promo{
		Code:     p.Code,
		PriceCNY: p.PriceCNY.V,
		Limit:    p.LimitCount,
		NewUser:  p.NewUserOnly,
		End:      p.EndTime,
	}
}

func (s *Service) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "who-dat/2.0 (+https://github.com/niesgeek/who-dat)")
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("price upstream: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("price upstream status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("price upstream decode: %w", err)
	}
	return nil
}

func effFor(r *listRow, order string) *float64 {
	switch order {
	case "register":
		return r.RegisterEff.V
	case "renew":
		return r.RenewEff.V
	default:
		return r.TransferEff.V
	}
}

func cnyFor(r *listRow, order string) *float64 {
	switch order {
	case "register":
		return r.RegisterCNY.V
	case "renew":
		return r.RenewCNY.V
	default:
		return r.TransferCNY.V
	}
}

func origFor(r *listRow, order string) *float64 {
	switch order {
	case "register":
		return r.Register.V
	case "renew":
		return r.Renew.V
	default:
		return r.Transfer.V
	}
}

func hasPromo(r *listRow, order string) bool {
	switch order {
	case "register":
		return r.PromoCode.Register
	case "renew":
		return r.PromoCode.Renew
	default:
		return r.PromoCode.Transfer
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
