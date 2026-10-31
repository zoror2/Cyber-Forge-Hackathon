package mockvendor

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestIncrementalDemoStablePagination(t *testing.T) {
	h := Handler()
	upper := time.Now().UTC().Add(time.Hour)
	read := func(upper time.Time, page string) []map[string]any {
		t.Helper()
		q := url.Values{"updated_since": {"2020-01-01T00:00:00Z"}, "updated_before": {upper.Format(time.RFC3339Nano)}, "page": {page}, "per_page": {"2"}}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/incremental/users?"+q.Encode(), nil))
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		var rows []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	if rows := read(upper, "1"); len(rows) != 2 {
		t.Fatal(rows)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/incremental/advance", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	// A mutation between pages cannot change an already-open window's snapshot.
	if rows := read(upper, "2"); len(rows) != 1 || rows[0]["id"] != "3" {
		t.Fatal("snapshot changed mid-page", rows)
	}
	if rows := read(upper.Add(time.Minute), "2"); len(rows) != 2 || rows[1]["id"] != "4" {
		t.Fatal("new window missed new record", rows)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/incremental/users?updated_since=invalid", nil))
	if w.Code != 400 {
		t.Fatal("invalid filter accepted")
	}
}
