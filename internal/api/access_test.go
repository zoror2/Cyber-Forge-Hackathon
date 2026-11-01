package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAllRoutesRequireTenantKey(t *testing.T) {
	key := strings.Repeat("test-key-", 5)
	// Limits{} = unlimited: this test sends many bad keys from one address on purpose.
	handler, e := New(&API{Limits: &Limits{}, Authenticate: func(_ context.Context, k string) (string, error) {
		if k == key {
			return "tenant-a", nil
		}
		return "", errors.New("invalid")
	}})
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/health", "/configs", "/configs/x/validate", "/configs/x/activate", "/configs/x/test", "/secrets", "/secrets/x", "/connectors/x/test", "/connectors/x/run", "/connectors/x/sync-state", "/runs", "/records/vulnerability_finding", "/records/user_inventory", "/records/inventory_info", "/schema/users", "/ai/draft", "/quarantine", "/alerts", "/notifications/status", "/exposure", "/ai/audit", "/unknown"} {
		for _, auth := range []string{"", "Bearer wrong", "Bearer " + strings.Repeat("bad", 20)} {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Authorization", auth)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("%s -> %d", path, w.Code)
			}
		}
	}
	browser := []struct {
		origin, site string
		allowed      bool
	}{
		{"https://attacker.invalid", "", false},
		{"https://attacker.invalid", "cross-site", false},
		{"http://example.com", "cross-site", false}, // spoofed host, but the browser says cross-site
		{"http://example.com", "same-site", false},
		{"", "cross-site", false},
		{"", "same-site", false},
		{"http://example.com", "same-origin", true}, // bundled UI (httptest host is example.com)
		{"", "", true}, // curl / Postman
	}
	for _, b := range browser {
		r := httptest.NewRequest("POST", "/configs/x/validate", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		if b.origin != "" {
			r.Header.Set("Origin", b.origin)
		}
		if b.site != "" {
			r.Header.Set("Sec-Fetch-Site", b.site)
		}
		w := httptest.NewRecorder()
		func() {
			defer func() { recover() }() // allowed requests reach a handler with no store
			handler.ServeHTTP(w, r)
		}()
		if (w.Code == 403) == b.allowed {
			t.Fatalf("%+v -> %d", b, w.Code)
		}
	}
	if _, e = New(&API{}); e == nil {
		t.Fatal("missing auth store accepted")
	}
}
