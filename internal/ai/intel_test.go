package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAcquisitionsKeepOnlyQuotesFoundOnTheCitedPage(t *testing.T) {
	answer := "OWNS: Splunk | 2024 | https://newsroom.cisco.com/splunk | Cisco completed its acquisition of Splunk, the cybersecurity leader.\n" +
		"OWNS: FakeCo | 2025 | https://newsroom.cisco.com/fake | Cisco completed its acquisition of FakeCo for billions.\n" + // not on page
		"OWNS: Duo | 2018 | https://newsroom.cisco.com/duo | The company announced record quarterly revenue today.\n" + // no acquisition, no names
		"OWNS: Evil | 2020 | http://insecure.example/x | Cisco completed its acquisition of Evil Corp today."
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"usageMetadata": map[string]int{"promptTokenCount": 5, "totalTokenCount": 9},
			"candidates": []any{map[string]any{"finishReason": "STOP", "content": map[string]any{"parts": []any{map[string]any{"text": answer}}}}}})
	}))
	defer srv.Close()
	c := NewGemini("k", "m")
	c.URL, c.HTTP = srv.URL+"/", srv.Client()
	c.FetchDocumentation = func(_ context.Context, u string) (string, error) {
		return "<p>News: Cisco completed its acquisition of   Splunk, the cybersecurity leader. The company announced record quarterly revenue today.</p>", nil
	}
	got, usage, e := c.Acquisitions(context.Background(), "Cisco", nil)
	if e != nil || len(got) != 1 || got[0].Company != "Splunk" || got[0].Date != "2024" || usage.Total != 9 {
		t.Fatal(got, usage, e)
	}
	if _, _, e := New("k", "m").Acquisitions(context.Background(), "Cisco", nil); e == nil {
		t.Fatal("non-search provider must refuse")
	}
}

func TestIncidentsNeedCompanyAndAttackInQuote(t *testing.T) {
	answer := "INCIDENT: ArcaneDoor | 2024-04 | https://blog.talosintelligence.com/a | Threat actors exploited Cisco ASA devices in the ArcaneDoor campaign.\n" +
		"INCIDENT: Earnings | 2024-05 | https://blog.talosintelligence.com/b | Cisco reported strong earnings in the quarter overall."
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"usageMetadata": map[string]int{"promptTokenCount": 5, "totalTokenCount": 9},
			"candidates": []any{map[string]any{"finishReason": "STOP", "content": map[string]any{"parts": []any{map[string]any{"text": answer}}}}}})
	}))
	defer srv.Close()
	c := NewGemini("k", "m")
	c.URL, c.HTTP = srv.URL+"/", srv.Client()
	c.FetchDocumentation = func(context.Context, string) (string, error) {
		return "Threat actors exploited Cisco ASA devices in the ArcaneDoor campaign. Cisco reported strong earnings in the quarter overall.", nil
	}
	got, _, e := c.Incidents(context.Background(), "Cisco")
	if e != nil || len(got) != 1 || got[0].Title != "ArcaneDoor" || got[0].Company != "Cisco" {
		t.Fatal(got, e)
	}
}
