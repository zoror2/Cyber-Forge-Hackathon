package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEveryRouteRequiresAdmin(t *testing.T) {
	h, err := New(&API{}, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/health", "/configs", "/configs/x/validate", "/configs/x/activate", "/secrets", "/secrets/x", "/connectors/x/test", "/connectors/x/run", "/runs", "/records/users", "/quarantine", "/missing"} {
		for _, auth := range []string{"", "Bearer wrong"} {
			r := httptest.NewRequest("GET", route, nil)
			r.Header.Set("Authorization", auth)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("%s got %d", route, w.Code)
			}
		}
	}
	r := httptest.NewRequest("POST", "/configs", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	r.Header.Set("Origin", "https://attacker.invalid")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	if _, err := New(&API{}, ""); err == nil {
		t.Fatal("empty admin token accepted")
	}
}
