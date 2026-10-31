// mockvendor is a fake vendor API for testing failure handling from Postman.
// It is a test tool: never deploy it anywhere reachable from the internet.
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
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mu     sync.Mutex
	counts = map[string]int{}
)

func hit(key string) int {
	mu.Lock()
	defer mu.Unlock()
	counts[key]++
	return counts[key]
}

func intParam(r *http.Request, name string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(name)); err == nil {
		return v
	}
	return def
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

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

func window(total, start, size int) (int, int) {
	if start >= total || size < 1 {
		return start, 0
	}
	return start, min(size, total-start)
}

func main() {
	addr := os.Getenv("MOCK_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /users", func(w http.ResponseWriter, r *http.Request) {
		page, size := max(intParam(r, "page", 1), 1), intParam(r, "per_page", 10)
		start, n := window(25, (page-1)*size, size)
		if start+n < 25 {
			w.Header().Set("Link", fmt.Sprintf(`<http://%s/users?page=%d&per_page=%d>; rel="next"`, r.Host, page+1, size))
		}
		writeJSON(w, users(start+1, n))
	})

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

	mux.HandleFunc("GET /secure", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mock-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, users(1, 3))
	})

	mux.HandleFunc("GET /flaky", func(w http.ResponseWriter, r *http.Request) {
		key := "flaky:" + r.URL.Query().Get("key")
		if hit(key) <= intParam(r, "fail", 3) {
			w.WriteHeader(intParam(r, "code", 500))
			return
		}
		writeJSON(w, users(1, 3))
	})

	mux.HandleFunc("GET /ratelimit", func(w http.ResponseWriter, r *http.Request) {
		if hit("rl:"+r.URL.Query().Get("key")) == 1 {
			w.Header().Set("Retry-After", strconv.Itoa(intParam(r, "retry_after", 5)))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writeJSON(w, users(1, 3))
	})

	mux.HandleFunc("GET /hang", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Duration(intParam(r, "seconds", 60)) * time.Second):
			writeJSON(w, users(1, 1))
		}
	})

	mux.HandleFunc("GET /redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", http.StatusFound)
	})

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

	mux.HandleFunc("GET /malformed", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]any{
			{"id": 1, "email": "ok@example.com", "last_login": "2026-10-01T09:00:00Z"},
			{"email": "missing-id@example.com"},
			{"id": 3, "email": "bad-date@example.com", "last_login": "not-a-date"},
			{"id": 4, "email": nil},
		})
	})

	mux.HandleFunc("GET /offhost", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example/steal?page=2>; rel="next"`)
		writeJSON(w, users(1, 10))
	})

	mux.HandleFunc("POST /reset", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counts = map[string]int{}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("mockvendor listening on %s (TEST TOOL, do not deploy)", addr)
	log.Fatal(srv.ListenAndServe())
}
