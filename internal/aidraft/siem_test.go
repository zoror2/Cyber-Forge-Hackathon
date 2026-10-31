package aidraft

import (
	"configbridge/internal/insights"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGroqSIEMEvidenceUsageAndOutputFailures(t *testing.T) {
	evidence := insights.Evidence{Topic: "connection_health", WindowHours: 24, Facts: []insights.Fact{{ID: "e1", Rule: "collection_failures", Severity: "warning", Category: "auth_failed", Count: 3}}}
	for _, scenario := range []string{"ok", "missing_usage", "invalid_usage", "bad_citation", "unknown_field", "markup", "truncated", "401", "429", "500"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				raw, _ := io.ReadAll(r.Body)
				if strings.Contains(string(raw), "SYNTHETIC_PROVIDER_KEY") || strings.Contains(string(raw), "tenant-a") {
					t.Error("private provider payload")
				}
				if r.Header.Get("Authorization") != "Bearer SYNTHETIC_PROVIDER_KEY" {
					t.Error("auth missing")
				}
				if scenario == "401" || scenario == "429" || scenario == "500" {
					code := 500
					if scenario == "401" {
						code = 401
					}
					if scenario == "429" {
						code = 429
					}
					w.WriteHeader(code)
					fmt.Fprint(w, "SYNTHETIC_PROVIDER_KEY")
					return
				}
				a := map[string]any{"summary": "The sampled runs failed authentication; check expiry and permissions.", "evidence_ids": []string{"e1"}, "next_checks": []string{"credential_permissions"}}
				if scenario == "bad_citation" {
					a["evidence_ids"] = []string{"customer-id"}
				}
				if scenario == "unknown_field" {
					a["activate"] = true
				}
				if scenario == "markup" {
					a["summary"] = "<script>"
				}
				b, _ := json.Marshal(a)
				finish := "stop"
				if scenario == "truncated" {
					finish = "length"
				}
				result := map[string]any{"choices": []any{map[string]any{"finish_reason": finish, "message": map[string]any{"content": string(b)}}}}
				if scenario != "missing_usage" {
					total := 120
					if scenario == "invalid_usage" {
						total = 119
					}
					result["usage"] = map[string]int{"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": total}
				}
				json.NewEncoder(w).Encode(result)
			}))
			defer server.Close()
			g, err := NewGroq("SYNTHETIC_PROVIDER_KEY", DefaultModel)
			if err != nil {
				t.Fatal(err)
			}
			g.endpoint = server.URL
			g.client = server.Client()
			a, u, err := g.Explain(context.Background(), evidence)
			if scenario == "ok" || scenario == "missing_usage" {
				if err != nil || a.Validate(evidence) != nil {
					t.Fatal(err)
				}
				if scenario == "ok" && (!u.Valid() || u.Total != 120) {
					t.Fatal("usage lost", u)
				}
				if scenario == "missing_usage" && u.Known {
					t.Fatal("invented usage")
				}
			} else if err == nil || strings.Contains(err.Error(), "SYNTHETIC_PROVIDER_KEY") {
				t.Fatal("unsafe failure", err)
			}
			if calls != 1 {
				t.Fatal("implicit retries", calls)
			}
		})
	}
}
