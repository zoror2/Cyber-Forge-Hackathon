package tests

import (
	"configbridge/internal/ai"
	"configbridge/internal/api"
	"configbridge/internal/insights"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Uses both real provider adapters against deterministic HTTP stand-ins, with
// real Docker PostgreSQL/OpenSearch. It proves application flow and boundaries,
// not the quality/latency of an actual hosted model. No external AI call occurs.
func TestAILocalWorkflowsThroughOpenSearch(t *testing.T) {
	endpoint := os.Getenv("TEST_OPENSEARCH_URL")
	if endpoint == "" {
		t.Skip("real Docker OpenSearch required")
	}
	for _, provider := range []string{"groq", "gemini"} {
		t.Run(provider, func(t *testing.T) {
			started := time.Now()
			e := setup(t)
			const ref = "https://docs.fixturevendor.example/users"
			const example = `[{"id":1,"profile":{"name":"Public sample"},"email":"public@example.test","last_login":"2026-11-01T00:00:00Z"}]`
			const doc = "Public account users. GET /users . API base https://api.fixturevendor.example . No authentication. No pagination; single response. " + example
			candidate := userConfig("drafted_users", "https://api.fixturevendor.example/users")
			candidate.Schedule.Enabled = true // the backend must return a disabled draft
			candidate.Schedule.IntervalSeconds = 900
			proof := []ai.Evidence{
				{Kind: "endpoint", URL: ref, Quote: "Public account users. GET /users"},
				{Kind: "api_host", URL: ref, Quote: "API base https://api.fixturevendor.example"},
				{Kind: "auth", URL: ref, Quote: "No authentication"},
				{Kind: "scope", URL: ref, Quote: "Public account users"},
				{Kind: "dataset", URL: ref, Quote: "Public account users"},
				{Kind: "pagination", URL: ref, Quote: "No pagination; single response"},
				{Kind: "items_path", URL: ref, Quote: example},
			}
			for _, field := range []string{"id", "profile.name", "email", "last_login"} {
				proof = append(proof, ai.Evidence{Kind: "field", Value: field, URL: ref, Quote: example})
			}
			var mu sync.Mutex
			prompts := []string{}
			draftCalls, explainCalls := 0, 0
			model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				prompts = append(prompts, string(body))
				var answer any
				if strings.Contains(string(body), `"evidence_ids"`) {
					explainCalls++
					answer = map[string]any{"summary": "Six authentication failures and one source-reported high-severity event were found; an attack is not established.", "evidence_ids": []string{"e1", "e2"}, "next_checks": []string{"event_review", "authentication_review"}}
				} else {
					draftCalls++
					proposal := candidate
					if draftCalls == 1 {
						proposal.Request.Method = "POST"
					} else if !strings.Contains(string(body), "request.method") {
						t.Error("validator feedback missing from repair")
					}
					cfgJSON, _ := json.Marshal(proposal)
					answer = map[string]any{"config_json": string(cfgJSON), "evidence": proof, "notes": []string{"unverified model note"}, "needed": []string{}, "optional": []string{}, "sources": []string{ref}, "also_available": []string{}, "tenant_hint": "", "plan": "standard"}
				}
				text, _ := json.Marshal(answer)
				w.Header().Set("Content-Type", "application/json")
				if provider == "gemini" {
					if r.Header.Get("x-goog-api-key") != "SYNTHETIC_AI_KEY" {
						t.Error("Gemini header missing")
					}
					json.NewEncoder(w).Encode(map[string]any{"candidates": []any{map[string]any{"finishReason": "STOP", "content": map[string]any{"parts": []any{map[string]string{"text": string(text)}}}}}, "usageMetadata": map[string]int{"promptTokenCount": 11, "totalTokenCount": 33}})
				} else {
					if r.Header.Get("Authorization") != "Bearer SYNTHETIC_AI_KEY" {
						t.Error("Groq header missing")
					}
					json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": string(text)}}}, "usage": map[string]int{"prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33}})
				}
			}))
			defer model.Close()
			client := ai.New("SYNTHETIC_AI_KEY", "fixture-model")
			if provider == "gemini" {
				client = ai.NewGemini("SYNTHETIC_AI_KEY", "fixture-model")
			}
			client.URL = model.URL + "/"
			client.DailyLimit = 20
			client.TokenLimit = 400000
			client.FetchDocumentation = func(context.Context, string) (string, error) { return doc, nil }
			search, err := insights.NewSearch(endpoint, "", "", "dev", e.db.Schema, nil)
			if err != nil {
				t.Fatal(err)
			}
			h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc, Limits: &api.Limits{}, AI: client, SIEM: &api.SIEM{Search: search, Provider: client, EnabledTenants: map[string]bool{"tenant-a": true, "tenant-b": true}, DailyCalls: 20, DailyTokens: 400000}})
			if err != nil {
				t.Fatal(err)
			}
			e.api.Close()
			e.api = httptest.NewServer(h)
			defer e.api.Close()
			var draft ai.Draft
			body, _ := json.Marshal(ai.Request{Product: "FixtureVendor", Data: "user_inventory", Dataset: "account users", Scope: "account", Details: "PRIVATE_CUSTOMER_NOTES", DocumentationURLs: []string{ref}})
			if err := json.Unmarshal(e.request(t, "tenant-a", "POST", "/ai/draft", body, 200), &draft); err != nil {
				t.Fatal(err)
			}
			if draft.Rounds != 2 || draft.Contract == nil || len(draft.Evidence) < 6 {
				t.Fatal("repair/evidence missing")
			}
			var draftUsage store.AIConsumption
			if err := json.Unmarshal(e.request(t, "tenant-a", "GET", "/ai/usage", nil, 200), &draftUsage); err != nil || draftUsage.ReportedTokens != 66 {
				t.Fatal("draft repair usage missing", draftUsage, err)
			}
			cfg, issues := config.Decode(draft.Config)
			if len(issues) != 0 || cfg.Schedule.Enabled || cfg.Request.Method != "GET" {
				t.Fatal("unsafe returned draft", issues)
			}
			if list := e.request(t, "tenant-a", "GET", "/configs", nil, 200); strings.TrimSpace(string(list)) != "[]" {
				t.Fatal("AI saved a draft automatically")
			}
			cfg.Request.URL = e.vendor.URL + "/clean"
			cfg.Request.AllowedPorts = []int{portOf(cfg.Request.URL)}
			revision := e.save(t, "tenant-a", cfg, false)
			previewBody, _ := json.Marshal(map[string]int{"revision": revision})
			e.request(t, "tenant-a", "POST", "/configs/"+cfg.ID+"/test", previewBody, 200)
			e.request(t, "tenant-a", "POST", "/configs/"+cfg.ID+"/activate", previewBody, 200)
			if run := e.run(t, "tenant-a", cfg.ID, 200); run.Accepted != 1 || run.Quarantined != 0 {
				t.Fatal(run)
			}
			security := securityConfig(t, e, "private_events")
			e.save(t, "tenant-a", security, true)
			e.run(t, "tenant-a", security.ID, 200)
			var response api.SIEMResponse
			if err := json.Unmarshal(e.request(t, "tenant-a", "POST", "/siem/ask", question(security.ID, "security_findings"), 200), &response); err != nil {
				t.Fatal(err)
			}
			counts := map[string]int64{}
			for _, fact := range response.Evidence.Facts {
				counts[fact.Rule] = fact.Count
			}
			if response.Status != "explanation_requires_review" || counts["authentication_failures"] != 6 || counts["high_severity_events"] != 1 || len(response.Answer.EvidenceIDs) != 2 {
				t.Fatal("wrong retrieved facts/citations", response)
			}
			var usage store.AIConsumption
			if err := json.Unmarshal(e.request(t, "tenant-a", "GET", "/ai/usage", nil, 200), &usage); err != nil || usage.ReportedTokens != 99 || usage.Requests != 2 || usage.UnreportedReserved != 0 {
				t.Fatal("shared usage wrong", usage, err)
			}
			e.request(t, "tenant-b", "POST", "/siem/ask", question(security.ID, "security_findings"), 404)
			e.request(t, "tenant-a", "POST", "/siem/ask", []byte(`{"connector":"private_events","topic":"security_findings","external_ai_consent":true,"sql":"SELECT all private data"}`), 400)
			mu.Lock()
			defer mu.Unlock()
			if draftCalls != 2 || explainCalls != 1 {
				t.Fatal("unexpected model calls", draftCalls, explainCalls)
			}
			for _, prompt := range prompts {
				for _, private := range []string{"PRIVATE_CUSTOMER_NOTES", "PRIVATE_CUSTOMER_NAME", "SYNTHETIC_PRIVATE_DESCRIPTION", "user@example.invalid", "192.0.2.1", "private_events", "tenant-a", key("tenant-a")} {
					if strings.Contains(prompt, private) {
						t.Fatal("private data crossed model boundary")
					}
				}
			}
			t.Logf("adapter=%s draft_rounds=%d selected_facts=%d reported_tokens=%d local_workflow_duration=%s; provider responses simulated, not a live model benchmark", provider, draft.Rounds, len(response.Evidence.Facts), usage.ReportedTokens, time.Since(started).Round(time.Millisecond))
		})
	}
}
