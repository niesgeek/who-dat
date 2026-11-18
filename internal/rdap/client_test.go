package rdap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lissy93/who-dat/internal/domain"
	"github.com/lissy93/who-dat/internal/srcerr"
)

func TestClient501FallsBackToWhois(t *testing.T) {
	// RDAP server that refuses the query with 501 (like rdap.hostmaster.ua
	// does for third-level pp.ua names).
	rdapTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(`{"errorCode":501,"title":"Not Implemented"}`))
	}))
	defer rdapTS.Close()

	// Fake IANA registry pointing .ua at that server.
	ianaTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"services":[[["ua"],["%s/"]]]}`, rdapTS.URL)
	}))
	defer ianaTS.Close()

	c := &Client{http: ianaTS.Client(), bootstrap: newBootstrap(ianaTS.Client())}
	c.bootstrap.url = ianaTS.URL

	n, _ := domain.Parse("test.pp.ua")
	_, err := c.Lookup(context.Background(), n)
	if !errors.Is(err, srcerr.ErrNoSource) {
		t.Fatalf("Lookup err = %v, want ErrNoSource (so the orchestrator falls back to WHOIS)", err)
	}
}
