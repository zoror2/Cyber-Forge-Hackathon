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
	handler, e := New(&API{Authenticate: func(_ context.Context, k string) (string, error) {
		if k == key {
			return "tenant-a", nil
		}
		return "", errors.New("invalid")
	}})
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/health", "/configs", "/configs/x/validate", "/configs/x/activate", "/secrets", "/secrets/x", "/connectors/x/test", "/connectors/x/run", "/runs", "/records/vulnerability_finding", "/records/user_inventory", "/records/inventory_info", "/quarantine", "/unknown"} {
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
	r := httptest.NewRequest("POST", "/configs", nil)
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Origin", "https://attacker.invalid")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	if _, e = New(&API{}); e == nil {
		t.Fatal("missing auth store accepted")
	}
}
