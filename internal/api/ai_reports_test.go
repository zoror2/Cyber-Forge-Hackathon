package api

import (
	"configbridge/internal/store"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAIReportFiltersAndOperatorFailClosed(t *testing.T) {
	today := time.Now().UTC().Format(time.DateOnly)
	for _, query := range []string{"", "?from=" + today + "&to=" + today, "?limit=100&offset=100000"} {
		if _, ok := parseAIReport(httptest.NewRequest("GET", "/ai/consumption"+query, nil), false); !ok {
			t.Fatal(query)
		}
	}
	for _, query := range []string{"?from=bad", "?to=9999-01-01", "?from=2026-02-30", "?customer=a", "?offset=x", "?limit=1&limit=2", "?limit=%ZZ", "?limit=5;customer=other", "?from=2020-01-02&to=2020-01-01"} {
		if _, ok := parseAIReport(httptest.NewRequest("GET", "/ai/consumption"+query, nil), false); ok {
			t.Fatal("accepted", query)
		}
	}
	h, e := New(&API{Store: &store.Store{}, Limits: &Limits{}})
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/operator/ai/consumption", nil))
	if w.Code != 503 {
		t.Fatal("unconfigured operator did not fail closed", w.Code)
	}
}
