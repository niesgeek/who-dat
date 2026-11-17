package price

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const listJSON = `{"code":100,"data":{"count":3,"domain":"com","order":"register","page":1,"total":3,"price":[
{"registrar":"spaceship","registrarname":"Spaceship","registrarweb":"https://www.spaceship.com/","currency":"usd","register":9.68,"register_cny":64.52,"register_eff_cny":21.2,"renew":10.88,"renew_cny":72.52,"renew_eff_cny":72.52,"transfer":10.38,"transfer_cny":69.19,"transfer_eff_cny":26.26,"promocode":{"register":true,"renew":false,"transfer":true},"updatedtime":"2026-11-17 21:40:33"},
{"registrar":"porkbun","registrarname":"Porkbun","registrarweb":"https://porkbun.com/","currency":"usd","register":10.5,"register_cny":70,"register_eff_cny":70,"renew":9,"renew_cny":60,"renew_eff_cny":60,"transfer":"n/a","transfer_cny":"n/a","transfer_eff_cny":"n/a","promocode":{"register":false,"renew":false,"transfer":false},"updatedtime":"2026-11-17 21:40:33"},
{"registrar":"tfhost","registrarname":"TFhost","registrarweb":"https://tfhost.ng/","currency":"ngn","register":"n/a","register_cny":"n/a","register_eff_cny":"n/a","renew":8049,"renew_cny":39.86,"renew_eff_cny":39.86,"transfer":100,"transfer_cny":80,"transfer_eff_cny":80,"promocode":{"register":false,"renew":false,"transfer":false},"updatedtime":"2026-11-17 21:40:39"}
]}}`

func TestCheapestPicksLowestEffectivePerOrder(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		q := r.URL.Query()
		if q.Get("registrar") == "spaceship" && q.Get("order") == "register" {
			fmt.Fprint(w, `{"code":100,"data":{"promocode":true,"promos":[{"code":"COMPROS","price_cny":21.2,"limit_count":1,"new_user_only":false,"endtime":""}]}}`)
			return
		}
		if q.Get("registrar") == "spaceship" && q.Get("order") == "transfer" {
			fmt.Fprint(w, `{"code":100,"data":{"promocode":true,"promos":[{"code":"SPSCOMTR","price_cny":26.26,"limit_count":1,"new_user_only":false,"endtime":""}]}}`)
			return
		}
		if q.Get("domain") == "com" {
			fmt.Fprint(w, listJSON)
			return
		}
		t.Errorf("unexpected upstream query %s", r.URL.RawQuery)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	svc := NewWithBase(srv.Client(), srv.URL, 5*time.Minute)
	res, err := svc.Cheapest(t.Context(), "com")
	if err != nil {
		t.Fatalf("Cheapest: %v", err)
	}
	if !res.OK || res.TLD != "com" || res.Total != 3 {
		t.Fatalf("unexpected response: %+v", res)
	}
	if res.Source != "nazhumi.com" || !strings.Contains(res.SourceURL, "nazhumi.com/domain/com") {
		t.Errorf("source attribution missing: %+v", res)
	}
	byOrder := map[string]Quote{}
	for _, it := range res.Items {
		byOrder[it.Order] = it
	}
	reg := byOrder["register"]
	if reg.Empty || reg.RegistrarName != "Spaceship" || reg.EffectiveCNY == nil || *reg.EffectiveCNY != 21.2 {
		t.Errorf("register cheapest = %+v, want Spaceship 21.2", reg)
	}
	if reg.Promo == nil || reg.Promo.Code != "COMPROS" || reg.Promo.Limit != 1 {
		t.Errorf("register promo = %+v, want COMPROS limit 1", reg.Promo)
	}
	if reg.StandardCNY == nil || *reg.StandardCNY != 64.52 {
		t.Errorf("register standardCny = %v, want 64.52", reg.StandardCNY)
	}
	ren := byOrder["renew"]
	if ren.Empty || ren.RegistrarName != "TFhost" || ren.EffectiveCNY == nil || *ren.EffectiveCNY != 39.86 {
		t.Errorf("renew cheapest = %+v, want TFhost 39.86", ren)
	}
	if ren.Promo != nil {
		t.Errorf("renew promo should be nil, got %+v", ren.Promo)
	}
	tr := byOrder["transfer"]
	if tr.Empty || tr.RegistrarName != "Spaceship" || tr.EffectiveCNY == nil || *tr.EffectiveCNY != 26.26 {
		t.Errorf("transfer cheapest = %+v, want Spaceship 26.26", tr)
	}
	if tr.Promo == nil || tr.Promo.Code != "SPSCOMTR" {
		t.Errorf("transfer promo = %+v, want SPSCOMTR", tr.Promo)
	}

	// Second call is served from cache: no further upstream hits (1 list + 2 promos).
	if got := hits.Load(); got != 3 {
		t.Fatalf("upstream hits = %d, want 3", got)
	}
	if _, err := svc.Cheapest(t.Context(), "com"); err != nil {
		t.Fatalf("cached Cheapest: %v", err)
	}
	if got := hits.Load(); got != 3 {
		t.Errorf("cached call hit upstream: hits = %d, want 3", got)
	}
}

func TestCheapestUnlistedSuffix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":100,"data":{"count":0,"domain":"zzz","order":"register","page":1,"total":0,"price":[]}}`)
	}))
	defer srv.Close()

	svc := NewWithBase(srv.Client(), srv.URL, 5*time.Minute)
	res, err := svc.Cheapest(t.Context(), "zzz")
	if err != nil {
		t.Fatalf("Cheapest: %v", err)
	}
	if !res.OK || res.Total != 0 {
		t.Fatalf("unexpected response: %+v", res)
	}
	for _, it := range res.Items {
		if !it.Empty {
			t.Errorf("order %s should be empty for unlisted suffix: %+v", it.Order, it)
		}
	}
}

func TestCheapestUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":201,"msg":"参数错误"}`)
	}))
	defer srv.Close()

	svc := NewWithBase(srv.Client(), srv.URL, 5*time.Minute)
	if _, err := svc.Cheapest(t.Context(), "com"); err == nil {
		t.Error("expected error for upstream code 201")
	}
}

func TestValidSuffix(t *testing.T) {
	for _, ok := range []string{"com", "co.uk", "xn--fiqs8s", "com.cn"} {
		if !ValidSuffix(ok) {
			t.Errorf("ValidSuffix(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", ".", "com/", "exa mple.com", "-com", "com..uk", "https://example.com"} {
		if ValidSuffix(bad) {
			t.Errorf("ValidSuffix(%q) = true, want false", bad)
		}
	}
}
