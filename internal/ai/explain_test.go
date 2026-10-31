package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"configbridge/configs"
	"configbridge/internal/insights"
)

// groqFake answers every call with content and reports usage (nil = none).
func groqFake(t *testing.T, content string, usage map[string]int64) (*Client, *[]string) {
	seen := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, string(b))
		out := map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": content}}}}
		if usage != nil {
			out["usage"] = usage
		}
		json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	c := New("test-key", "m")
	c.URL = srv.URL
	return c, &seen
}

var evidence = insights.Evidence{Topic: "security_findings", WindowHours: 24, Facts: []insights.Fact{{ID: "e1", Rule: "high_severity_events", Severity: "high", Category: "source_high_severity", Count: 1}}}

func TestExplainValidatesAnswerAndReportsUsage(t *testing.T) {
	good := `{"summary":"One high-severity event was reported; its cause is not established.","evidence_ids":["e1"],"next_checks":["event_review"]}`
	c, seen := groqFake(t, good, map[string]int64{"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120})
	a, u, err := c.Explain(context.Background(), evidence)
	if err != nil || a.EvidenceIDs[0] != "e1" || !u.Known || u.Total != 120 {
		t.Fatal(a, u, err)
	}
	if !strings.Contains((*seen)[0], `"name":"siem_explanation"`) || !strings.Contains((*seen)[0], `"strict":true`) {
		t.Fatal("explanation schema not sent")
	}
	// citations that are not in the evidence, links and extra fields are refused,
	// but the tokens they cost are still reported
	for _, bad := range []string{
		`{"summary":"x","evidence_ids":["e9"],"next_checks":[]}`,
		`{"summary":"see https://evil.invalid","evidence_ids":["e1"],"next_checks":[]}`,
		`{"summary":"x","evidence_ids":["e1"],"next_checks":[],"action":"disable_alerts"}`,
	} {
		c, _ := groqFake(t, bad, map[string]int64{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})
		if _, u, err := c.Explain(context.Background(), evidence); !errors.Is(err, insights.ErrEvidence) || u.Total != 2 {
			t.Fatal("bad answer accepted", bad, u, err)
		}
	}
	if _, _, err := c.Explain(context.Background(), insights.Evidence{Topic: "security_findings"}); !errors.Is(err, insights.ErrEvidence) {
		t.Fatal("invalid evidence sent to the model")
	}
}

func TestDraftUsageSummedAndUnknownWhenMissing(t *testing.T) {
	out, _ := json.Marshal(map[string]any{"config_json": string(configs.GitHubMembers), "notes": []string{}, "needed": []string{}, "optional": []string{}, "sources": []string{}, "also_available": []string{}, "tenant_hint": "", "plan": "standard"})
	c, _ := groqFake(t, string(out), map[string]int64{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})
	d, err := c.Draft(context.Background(), Request{Product: "GitHub", Data: "user_inventory"}, nil)
	if err != nil || !d.Usage.Known || d.Usage.Total != 15 {
		t.Fatal(d, err)
	}
	c, _ = groqFake(t, string(out), nil)
	if d, err = c.Draft(context.Background(), Request{Product: "GitHub", Data: "user_inventory"}, nil); err != nil || d.Usage.Known {
		t.Fatal("missing usage reported as known", d.Usage, err)
	}
}
