package tests

import (
	"configbridge/pkg/config"
	"configbridge/pkg/ocsf"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// Real TLS engine + mapper + API + Docker PostgreSQL, with a documented
// Elasticsearch response shape. This is not a live Elastic Security account.
func TestVendorElasticSearchContractThroughStorage(t *testing.T) {
	e := setup(t)
	raw, err := os.ReadFile("../configs/elastic_security_alerts.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, issues := config.Decode(raw)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	var unauthorized atomic.Bool
	var partial atomic.Bool
	var vendorCalls atomic.Int32
	row := func(id, title, severity string) map[string]any {
		return map[string]any{"_id": id, "fields": map[string]any{"kibana.alert.rule.name": []any{title}, "kibana.alert.severity": []any{severity}, "@timestamp": []any{"2026-11-01T00:00:00Z"}}}
	}
	rows := []any{row("alert-1", "First rule", "high"), row("alert-2", "Second rule", "low"), row("alert-3", "Third rule", "critical"), row("", "Bad identity", "high")}
	vendor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vendorCalls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/.alerts-security.alerts-default/_search" {
			t.Error("unexpected method or path")
			w.WriteHeader(400)
			return
		}
		if unauthorized.Load() || r.Header.Get("Authorization") != "ApiKey SYNTHETIC_ELASTIC_KEY" {
			w.WriteHeader(401)
			return
		}
		q := r.URL.Query()
		var source map[string]any
		if q.Get("source_content_type") != "application/json" || json.Unmarshal([]byte(q.Get("source")), &source) != nil || source["_source"] != false || q.Get("allow_partial_search_results") != "false" {
			t.Error("missing explicit field-only/complete-search contract")
			w.WriteHeader(400)
			return
		}
		from, err := strconv.Atoi(q.Get("from"))
		if err != nil || from < 0 {
			w.WriteHeader(400)
			return
		}
		size, err := strconv.Atoi(q.Get("size"))
		if err != nil || size != 2 {
			w.WriteHeader(400)
			return
		}
		from = min(from, len(rows))
		end := min(from+size, len(rows))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"timed_out": partial.Load(), "_shards": map[string]int{"failed": 0}, "hits": map[string]any{"hits": rows[from:end]}})
	}))
	defer vendor.Close()
	e.requests.Policy.RootCAs = vendor.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	cfg.Request.URL = vendor.URL + "/.alerts-security.alerts-default/_search"
	cfg.Request.AllowedPorts = []int{portOf(cfg.Request.URL)}
	cfg.Pagination.PageSize = 2
	cfg.Retry.MaxAttempts = 1
	secretBody, _ := json.Marshal(map[string]string{"value": "SYNTHETIC_ELASTIC_KEY", "allowed_host": strings.TrimPrefix(vendor.URL, "https://")})
	e.request(t, "tenant-a", "PUT", "/secrets/elastic_security", secretBody, 204)
	e.save(t, "tenant-a", cfg, true)
	e.request(t, "tenant-a", "POST", "/connectors/elastic_security_alerts/test", nil, 200)
	scope := e.db.Store.ForTenant("tenant-a")
	stored, err := scope.Records(context.Background(), 2004, cfg.ID, 100, 0)
	if err != nil || len(stored) != 0 {
		t.Fatal("preview persisted records", err)
	}
	for i := 0; i < 2; i++ {
		run := e.run(t, "tenant-a", cfg.ID, 200)
		if run.Accepted != 3 || run.Quarantined != 1 || run.Pages != 3 || run.Outcome != "completed_with_errors" {
			t.Fatal(run)
		}
	}
	stored, err = scope.Records(context.Background(), 2004, cfg.ID, 100, 0)
	if err != nil || len(stored) != 3 {
		t.Fatal("missing records/duplicates", len(stored), err)
	}
	for _, raw := range stored {
		var record map[string]any
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		if ocsf.Get(record, "finding_info.title") == nil || record["severity_id"] == float64(0) {
			t.Fatal("dotted vendor fields lost", record)
		}
	}
	e.request(t, "tenant-b", "GET", "/records/detection_finding?source="+cfg.ID, nil, 404)
	partial.Store(true)
	partialRun := e.run(t, "tenant-a", cfg.ID, 502)
	if partialRun.Outcome != "failed" || partialRun.Accepted != 0 {
		t.Fatal("HTTP-200 partial search treated as complete", partialRun)
	}
	partial.Store(false)
	unauthorized.Store(true)
	before := vendorCalls.Load()
	run := e.run(t, "tenant-a", cfg.ID, 502)
	if run.Outcome != "failed" || vendorCalls.Load() != before+1 {
		t.Fatal("bad credentials retried or marked healthy", run)
	}
	if strings.Contains(e.logs.String(), "SYNTHETIC_ELASTIC_KEY") {
		t.Fatal("credential leaked to logs")
	}
}
