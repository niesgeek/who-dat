package server

import (
	"net/http"
	"strings"

	"github.com/lissy93/who-dat/internal/price"
)

// handlePrice serves GET /api/price?tld=com, returning the cheapest registrar
// per order (register / renew / transfer) for one suffix. Prices come from the
// public nazhumi.com comparison API via the price service, which caches one
// suffix for five minutes; the response always names its source, so a price
// is never presented as this site's own quote.
func (s *server) handlePrice(w http.ResponseWriter, r *http.Request) {
	tld := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(r.URL.Query().Get("tld")), "."))
	if !price.ValidSuffix(tld) {
		writeError(w, http.StatusBadRequest, codeInvalidDomain, "invalid suffix", tld)
		return
	}
	res, err := s.prices.Cheapest(r.Context(), tld)
	if err != nil {
		writeError(w, http.StatusBadGateway, codeUpstreamError, "price source unavailable", tld)
		return
	}
	// A price snapshot, not a live quote: cacheable for five minutes only.
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, res)
}
