package insights

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSearchTransportPoliciesAndFailures(t *testing.T) {
	for _, url := range []string{"http://example.com", "http://localhost:9200", "https://u:p@example.com", "https://example.com/path", "https://example.com?q=secret", "file:///tmp/index"} {
		if _, e := NewSearch(url, "", "", "dev", "test", nil); e == nil {
			t.Fatal("unsafe endpoint accepted", url)
		}
	}
	if _, e := NewSearch("http://127.0.0.1:9200", "", "", "prod", "test", nil); e == nil {
		t.Fatal("production plaintext")
	}
	if _, e := NewSearch("http://127.0.0.1:9200", "u", "secret", "dev", "test", nil); e == nil {
		t.Fatal("plaintext auth")
	}
	for _, scenario := range []string{"ok", "error", "redirect", "oversized", "partial", "foreign", "stale", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			snap := Snapshot{Connector: "private_connector", Generation: "generation"}
			bodySeen := ""
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				bodySeen = string(b)
				if scenario == "redirect" {
					http.Redirect(w, r, "http://example.invalid", 302)
					return
				}
				if scenario == "error" {
					w.WriteHeader(500)
					fmt.Fprint(w, "PRIVATE_ERROR_BODY")
					return
				}
				if scenario == "oversized" {
					fmt.Fprint(w, strings.Repeat("x", (1<<20)+1))
					return
				}
				source := map[string]string{"id": Hash("f"), "tenant_hash": Hash("tenant-a"), "connector_hash": Hash(snap.Connector), "generation": snap.Generation}
				if scenario == "foreign" {
					source["tenant_hash"] = Hash("tenant-b")
				}
				if scenario == "stale" {
					source["generation"] = "old"
				}
				hits := []any{map[string]any{"_source": source}}
				if scenario == "duplicate" {
					hits = append(hits, hits[0])
				}
				failed := 0
				if scenario == "partial" {
					failed = 1
				}
				json.NewEncoder(w).Encode(map[string]any{"_shards": map[string]int{"failed": failed}, "hits": map[string]any{"hits": hits}})
			}))
			defer server.Close()
			s, e := NewSearch(server.URL, "", "", "dev", "test", nil)
			if e != nil {
				t.Fatal(e)
			}
			ids, e := s.Find(context.Background(), "tenant-a", snap, "connection_health")
			if scenario == "ok" || scenario == "duplicate" {
				if e != nil || len(ids) == 0 {
					t.Fatal(e)
				}
			} else if e == nil || strings.Contains(e.Error(), "PRIVATE_ERROR_BODY") {
				t.Fatal("unsafe search failure", e)
			}
			if strings.Contains(bodySeen, "private_connector") || strings.Contains(bodySeen, "tenant-a") || !strings.Contains(bodySeen, `"filter"`) {
				t.Fatal("query boundary", bodySeen)
			}
		})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer server.Close()
	s, _ := NewSearch(server.URL, "operator", "PRIVATE_PASSWORD", "prod", "test", nil)
	if _, e := s.Find(context.Background(), "tenant-a", Snapshot{}, "connection_health"); e == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", s, s), "PRIVATE_PASSWORD") {
		t.Fatal("password printed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if _, e := s.Find(ctx, "tenant-a", Snapshot{}, "connection_health"); e == nil || time.Since(started) > time.Second {
		t.Fatal("cancellation ignored")
	}
}
