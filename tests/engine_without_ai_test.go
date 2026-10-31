package tests

import (
	"encoding/json"
	"fmt"
	"testing"
)

// The collector has no dependency on an AI provider. This uses the real TLS
// engine, API, mapper and Docker PostgreSQL with API.AI left nil by setup.
func TestEngineCompleteFlowWithAIUnavailable(t *testing.T) {
	e := setup(t)
	e.request(t, "tenant-a", "POST", "/ai/draft", []byte(`{"product":"GitHub","data":"user_inventory"}`), 503)
	c := userConfig("without_ai", e.vendor.URL+"/clean")
	revision := e.save(t, "tenant-a", c, false)
	e.request(t, "tenant-a", "POST", "/configs/without_ai/test", []byte(fmt.Sprintf(`{"revision":%d}`, revision)), 200)
	var before []any
	json.Unmarshal(e.request(t, "tenant-a", "GET", "/runs", nil, 200), &before)
	if len(before) != 0 {
		t.Fatal("preview stored a production run")
	}
	e.request(t, "tenant-a", "POST", "/configs/without_ai/activate", []byte(fmt.Sprintf(`{"revision":%d}`, revision)), 200)
	for i := 0; i < 2; i++ {
		run := e.run(t, "tenant-a", "without_ai", 200)
		if run.Accepted != 1 || run.Quarantined != 0 || run.Outcome != "success" {
			t.Fatal(run)
		}
	}
	var rows []any
	json.Unmarshal(e.request(t, "tenant-a", "GET", "/records/user_inventory", nil, 200), &rows)
	if len(rows) != 1 {
		t.Fatal("deduplication failed without AI", len(rows))
	}
	var other []any
	json.Unmarshal(e.request(t, "tenant-b", "GET", "/records/user_inventory", nil, 200), &other)
	if len(other) != 0 {
		t.Fatal("tenant isolation failed")
	}
}
