package tests

import (
	"configbridge/configs"
	"configbridge/internal/ai"
	"configbridge/internal/api"
	"configbridge/internal/store"
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
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out, _ := json.Marshal(map[string]any{"config_json": content, "notes": []string{}, "needed": []string{}, "optional": []string{}, "sources": []string{}, "also_available": []string{}, "tenant_hint": "", "plan": "standard"})
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": string(out)}}},
			"usage": map[string]int64{"prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33}})
	}))
	defer model.Close()
	c := ai.New("SYNTHETIC_PROVIDER_KEY", "fixture")
	c.URL, c.DailyLimit, c.TokenLimit = model.URL, 5, 400000
	h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc, Limits: &api.Limits{}, AI: c})
	if err != nil {
		t.Fatal(err)
	}
	e.api.Close()
	e.api = httptest.NewServer(h)
	defer e.api.Close()
	body := []byte(`{"product":"GitHub","data":"user_inventory"}`)
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
}
