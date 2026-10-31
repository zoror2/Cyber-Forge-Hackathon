package tests

import (
	"configbridge/configs"
	"configbridge/internal/ai"
	"configbridge/internal/api"
	"configbridge/internal/store"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Drafts spend the same daily token budget as SIEM explanations; rejected
// drafts still record the tokens they cost.
func TestDraftUsageCountsValidatedAndRejectedOutputs(t *testing.T) {
	e := setup(t)
	content := string(configs.GitHubMembers)
	const ref = "https://docs.fixture.example/api"
	const example = `[{"id":1,"login":"demo","site_admin":false}]`
	const doc = "Public organization members. GET /orgs/owasp/members. API base https://api.github.com. Authentication: Bearer. Link pagination uses the Link header. per_page query parameter. " + example
	evidence := []ai.Evidence{{Kind: "query_param", Value: "per_page", URL: ref, Quote: "per_page query parameter"}, {Kind: "endpoint", Value: "https://api.github.com/orgs/owasp/members", URL: ref, Quote: "Public organization members. GET /orgs/owasp/members"}, {Kind: "api_host", Value: "api.github.com", URL: ref, Quote: "API base https://api.github.com"}, {Kind: "auth", Value: "bearer", URL: ref, Quote: "Authentication: Bearer"}, {Kind: "scope", Value: "organization", URL: ref, Quote: "Public organization members"}, {Kind: "dataset", Value: "organization members", URL: ref, Quote: "Public organization members"}, {Kind: "pagination", Value: "link", URL: ref, Quote: "Link pagination uses the Link header"}, {Kind: "items_path", Value: "", URL: ref, Quote: example}}
	for _, field := range []string{"id", "login", "site_admin"} {
		evidence = append(evidence, ai.Evidence{Kind: "field", Value: field, URL: ref, Quote: example})
	}
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out, _ := json.Marshal(map[string]any{"config_json": content, "notes": []string{}, "needed": []string{}, "optional": []string{}, "sources": []string{}, "also_available": []string{}, "tenant_hint": "", "plan": "standard", "evidence": evidence})
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": string(out)}}},
			"usage": map[string]int64{"prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33}})
	}))
	defer model.Close()
	c := ai.New("SYNTHETIC_PROVIDER_KEY", "fixture")
	c.URL, c.DailyLimit, c.TokenLimit = model.URL, 5, 400000
	c.FetchDocumentation = func(context.Context, string) (string, error) { return doc, nil }
	h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc, Limits: &api.Limits{}, AI: c})
	if err != nil {
		t.Fatal(err)
	}
	e.api.Close()
	e.api = httptest.NewServer(h)
	defer e.api.Close()
	body := []byte(`{"product":"FixtureVendor","data":"user_inventory","dataset":"organization members","scope":"organization","documentation_urls":["https://docs.fixture.example/api"]}`)
	e.request(t, "tenant-a", "POST", "/ai/draft", body, 200)
	content = `{"version":1,"id":"BAD ID"}` // rejected in every round (1 + 2 repairs)
	e.request(t, "tenant-a", "POST", "/ai/draft", body, 422)
	var usage store.AIConsumption
	if err := json.Unmarshal(e.request(t, "tenant-a", "GET", "/ai/usage", nil, 200), &usage); err != nil || usage.ReportedTokens != 33*4 || usage.Requests != 2 || usage.UnreportedReserved != 0 {
		t.Fatal("draft usage lost", usage, err)
	}
	var other store.AIConsumption
	json.Unmarshal(e.request(t, "tenant-b", "GET", "/ai/usage", nil, 200), &other)
	if other.Requests != 0 {
		t.Fatal("usage crossed tenant")
	}
	var report store.AIReport
	if err := json.Unmarshal(e.request(t, "tenant-a", "GET", "/ai/consumption", nil, 200), &report); err != nil || report.Summary.ReportedTokens != 33*4 || report.Summary.Requests != 2 || report.Summary.Failed != 1 || len(report.Requests) != 2 || len(report.Daily) != 7 {
		t.Fatal("dashboard disagrees with real draft/retry metering", report, err)
	}
}
