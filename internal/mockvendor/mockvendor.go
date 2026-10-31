// mockvendor is a fake vendor API for testing failure handling from Postman.
// It deliberately misbehaves on demand so we can prove the engine copes.
// It is a TEST TOOL: never deploy it anywhere reachable from the internet.
//
//	GET  /users?page=N&per_page=M          page numbers + Link header (25 users)
//	GET  /issues?startAt=N&maxResults=M    offset paging, Jira-style (25 issues)
//	GET  /events?after=CURSOR              cursor paging (14 events)
//	GET  /secure                           401 unless "Authorization: Bearer mock-token"
//	GET  /flaky?key=K&fail=N&code=500      fails N times per key, then succeeds
//	GET  /ratelimit?key=K&retry_after=5    429 + Retry-After once per key, then succeeds
//	GET  /hang?seconds=60                  never answers in time
//	GET  /redirect                         302 to the cloud metadata address
//	GET  /huge?mb=50                       streams a very large body
//	GET  /malformed                        records with missing / bad fields
//	GET  /offhost                          Link header pointing at another host
//	POST /reset                            clears flaky / ratelimit counters
package mockvendor

import (
	"encoding/json"
	"fmt"

	"net/http"

	"strconv"
	"strings"
	"sync"
	"time"
)

// counts remembers how many times each "key" was requested, so /flaky and
// /ratelimit can fail the first N calls and succeed afterwards.
var (
	mu     sync.Mutex // protects counts (requests arrive concurrently)
	counts = map[string]int{}
)

// hit increments and returns the call count for key.
func hit(key string) int {
	mu.Lock()
	defer mu.Unlock()
	counts[key]++
	return counts[key]
}

// intParam reads an integer query param, or returns def if missing/invalid.
func intParam(r *http.Request, name string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(name)); err == nil {
		return v
	}
	return def
}

// writeJSON sends v as a JSON response.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// users builds n fake user records starting at ID from. The nested "profile"
// and the RFC 3339 "last_login" exercise Member B's mapper (nested paths, dates).
func users(from, n int) []map[string]any {
	out := []map[string]any{}
	for i := from; i < from+n; i++ {
		out = append(out, map[string]any{
			"id": i, "login": fmt.Sprintf("user%02d", i), "email": fmt.Sprintf("user%02d@example.com", i),
			"profile":    map[string]any{"name": fmt.Sprintf("User %02d", i)},
			"last_login": time.Date(2026, 10, 1+i%28, 9, 30, 0, 0, time.UTC).Format(time.RFC3339),
		})
	}
	return out
}

// window returns which slice of a total-sized dataset a page covers:
// (start index, number of records). Returns 0 records past the end.
func window(total, start, size int) (int, int) {
	if start >= total || size < 1 {
		return start, 0
	}
	return start, min(size, total-start)
}

func Handler() http.Handler {
	mux := http.NewServeMux()

	// Page-number paging with a Link header, like GitHub.
	// Last page has no Link header, which tells the engine to stop.
	mux.HandleFunc("GET /users", func(w http.ResponseWriter, r *http.Request) {
		page, size := max(intParam(r, "page", 1), 1), intParam(r, "per_page", 10)
		start, n := window(25, (page-1)*size, size)
		if start+n < 25 {
			w.Header().Set("Link", fmt.Sprintf(`<https://%s/users?page=%d&per_page=%d>; rel="next"`, r.Host, page+1, size))
		}
		writeJSON(w, users(start+1, n))
	})

	// Offset paging like Jira: ?startAt=0&maxResults=10, records under "issues".
	mux.HandleFunc("GET /issues", func(w http.ResponseWriter, r *http.Request) {
		at, size := intParam(r, "startAt", 0), intParam(r, "maxResults", 10)
		start, n := window(25, at, size)
		issues := []map[string]any{}
		for i := start; i < start+n; i++ {
			issues = append(issues, map[string]any{"key": fmt.Sprintf("SEC-%d", i+1),
				"fields": map[string]any{"summary": "Issue " + strconv.Itoa(i+1), "priority": map[string]any{"name": "High"}, "created": "2026-10-20T10:00:00.000+0000"}})
		}
		writeJSON(w, map[string]any{"startAt": at, "maxResults": size, "total": 25, "issues": issues})
	})

	// Cursor paging: records under "data", next cursor at "meta.next".
	// Empty cursor on the last page means stop.
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("after") {
		case "":
			writeJSON(w, map[string]any{"data": users(1, 10), "meta": map[string]any{"next": "c2"}})
		case "c2":
			writeJSON(w, map[string]any{"data": users(11, 4), "meta": map[string]any{"next": ""}})
		default:
			http.Error(w, "bad cursor", http.StatusBadRequest)
		}
	})

	// Wrong/expired key test: only "Bearer mock-token" is accepted.
	// The engine must fail once with 401 and NOT retry.
	mux.HandleFunc("GET /secure", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mock-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, users(1, 3))
	})

	// Retry test: fails `fail` times (default 3) with status `code` (default 500)
	// for each distinct `key`, then succeeds. Use a new key per test run,
	// or POST /reset.
	mux.HandleFunc("GET /flaky", func(w http.ResponseWriter, r *http.Request) {
		key := "flaky:" + r.URL.Query().Get("scenario_id")
		if hit(key) <= intParam(r, "fail", 3) {
			w.WriteHeader(intParam(r, "code", 500))
			return
		}
		writeJSON(w, users(1, 3))
	})

	// Rate-limit test: first call per key returns 429 with Retry-After,
	// the next call succeeds. The engine must wait exactly that long.
	mux.HandleFunc("GET /ratelimit", func(w http.ResponseWriter, r *http.Request) {
		if hit("rl:"+r.URL.Query().Get("scenario_id")) == 1 {
			w.Header().Set("Retry-After", strconv.Itoa(intParam(r, "retry_after", 5)))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writeJSON(w, users(1, 3))
	})

	// Timeout test: waits `seconds` before answering (or until the client
	// gives up). The engine must time out and retry with backoff.
	mux.HandleFunc("GET /hang", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done(): // client disconnected
		case <-time.After(time.Duration(intParam(r, "seconds", 60)) * time.Second):
			writeJSON(w, users(1, 1))
		}
	})

	// SSRF test: redirects to the AWS metadata address. The engine must
	// refuse to follow it.
	mux.HandleFunc("GET /redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", http.StatusFound)
	})

	// Size-cap test: streams `mb` megabytes (default 50) of valid JSON.
	// The engine must stop reading at its limit and fail cleanly.
	mux.HandleFunc("GET /huge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := strings.Repeat(`{"id":1,"pad":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},`, 1000)
		fmt.Fprint(w, "[")
		for written := 0; written < intParam(r, "mb", 50)<<20; written += len(chunk) {
			if _, err := fmt.Fprint(w, chunk); err != nil {
				return // client gave up: that is the expected outcome
			}
		}
		fmt.Fprint(w, `{"id":2}]`)
	})

	// Bad-data test for Member B's mapper: one good record, then a missing
	// ID, an unparseable date and a null email. Bad ones must be quarantined
	// while the good one is stored.
	mux.HandleFunc("GET /malformed", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]any{
			{"id": 1, "email": "ok@example.com", "last_login": "2026-10-01T09:00:00Z"},
			{"email": "missing-id@example.com"},
			{"id": 3, "email": "bad-date@example.com", "last_login": "not-a-date"},
			{"id": 4, "email": nil},
		})
	})

	// Off-host pagination test: the "next page" link points at another
	// domain. The engine must refuse to follow it (credentials would leak).
	mux.HandleFunc("GET /offhost", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example/steal?page=2>; rel="next"`)
		writeJSON(w, users(1, 10))
	})

	// Reset all /flaky and /ratelimit counters between test runs.
	mux.HandleFunc("POST /reset", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counts = map[string]int{}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	return mux
}
