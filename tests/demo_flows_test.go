package tests

import (
	"configbridge/internal/ai"
	"configbridge/internal/api"
	"configbridge/internal/insights"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"configbridge/pkg/mapping"
	"configbridge/pkg/model"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestKEVExactCollectedMatchesIsolationAndProvenance(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	raw, err := os.ReadFile("../configs/cisa_kev.json")
	if err != nil {
		t.Fatal(err)
	}
	catalog, issues := config.Decode(raw)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	seed := func(tenant string, c config.Config, cves ...string) {
		t.Helper()
		s := e.db.Store.ForTenant(tenant)
		saved, err := s.SaveConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Activate(ctx, c.ID, saved.Revision); err != nil {
			t.Fatal(err)
		}
		run := model.Run{TenantID: tenant, ID: c.ID + "-run", Connector: c.ID, ConfigVersion: saved.Revision, ConfigHash: saved.Hash, Mode: "live", StartedAt: time.Now()}
		if err = s.StartRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		records := []model.Record{}
		for i, cve := range cves {
			rec, bad := mapping.Map(map[string]any{"cveID": cve, "vulnerabilityName": "Synthetic public fixture", "dateAdded": "2024-01-01", "vendorProject": "Unrelated name", "product": "Fixture"}, c, tenant, time.Now(), i)
			if bad != nil {
				t.Fatal(bad)
			}
			records = append(records, rec)
		}
		if err = s.SavePage(ctx, run.ID, c.ID, records, nil); err != nil {
			t.Fatal(err)
		}
		end := time.Now()
		run.EndedAt = &end
		run.Outcome = "success"
		run.Accepted = len(records)
		if err = s.FinishRun(ctx, run, 86400); err != nil {
			t.Fatal(err)
		}
	}
	seed("tenant-a", catalog, "CVE-2024-10001", "CVE-2024-10002")
	vendor := catalog
	vendor.ID = "scanner"
	vendor.Request.URL = "https://scanner.example/findings"
	seed("tenant-a", vendor, "CVE-2024-10001", "CVE-2024-99999")
	seed("tenant-b", vendor, "CVE-2024-10001")
	read := func(tenant string) store.KEVMatches {
		var out store.KEVMatches
		json.Unmarshal(e.request(t, tenant, "GET", "/kev/matches", nil, 200), &out)
		return out
	}
	a := read("tenant-a")
	if a.Total != 1 || a.CatalogEntries != 2 || len(a.Matches) != 1 || a.Matches[0].CVE != "CVE-2024-10001" || a.Matches[0].Connector != "scanner" {
		t.Fatalf("bad exact match: %+v", a)
	}
	if b := read("tenant-b"); b.Status != "catalog_missing" || b.Total != 0 {
		t.Fatal("cross tenant catalog", b)
	}
	seed("tenant-b", catalog, "CVE-2024-10002")
	if b := read("tenant-b"); b.Status != "no_matches" || b.Total != 0 {
		t.Fatal("same vendor or unrelated CVE matched", b)
	}
	// Catalog alone cannot be an affected customer asset.
	var only store.KEVMatches
	json.Unmarshal(e.request(t, "tenant-a", "GET", "/kev/matches?connector=cisa_kev", nil, 200), &only)
	if only.Total != 0 {
		t.Fatal("catalog self match")
	}
	e.request(t, "tenant-b", "GET", "/kev/matches?connector=foreign", nil, 404)
	e.request(t, "tenant-a", "GET", "/kev/matches?limit=501", nil, 400)
	var page store.KEVMatches
	json.Unmarshal(e.request(t, "tenant-a", "GET", "/kev/matches?offset=1&limit=1", nil, 200), &page)
	if page.Total != 1 || len(page.Matches) != 0 {
		t.Fatal("paging", page)
	}
	p := &explanationProvider{}
	siemAPI(t, e, &findingSearch{}, p)
	body := []byte(`{"connector":"scanner","topic":"security_findings","question":"What does this KEV match mean?","external_ai_consent":true}`)
	e.request(t, "tenant-a", "POST", "/siem/ask", body, 200)
	if p.calls != 1 || p.evidence.Question != "What does this KEV match mean?" || len(p.evidence.Facts) != 1 || p.evidence.Facts[0].Rule != "kev_exact_matches" {
		t.Fatalf("evidence %+v", p.evidence)
	}
	evidence, _ := json.Marshal(p.evidence)
	if !strings.Contains(string(evidence), "CVE-2024-10001") || strings.Contains(string(evidence), "scanner") {
		t.Fatal("customer identifiers sent to AI")
	}
	for _, q := range []string{"api_key=secret123", "Bearer private-key", "person@example.com", strings.Repeat("x", 1001), "\x00"} {
		b, _ := json.Marshal(map[string]any{"connector": "scanner", "topic": "security_findings", "question": q, "external_ai_consent": true})
		e.request(t, "tenant-a", "POST", "/siem/ask", b, 422)
	}
	if p.calls != 1 {
		t.Fatal("unsafe question reached model")
	}
	// Producing revision provenance, not a mutable display name.
	if _, err = e.db.Admin.Exec(ctx, "UPDATE "+e.db.Schema+".configs SET body=jsonb_set(body,'{request,url}','\"https://forged.example/feed\"') WHERE tenant_id='tenant-a' AND id='cisa_kev'"); err != nil {
		t.Fatal(err)
	}
	if x := read("tenant-a"); x.Total != 0 || x.Status != "catalog_missing" {
		t.Fatal("untrusted catalog", x)
	}
}

func TestQuarantineAIRepairPreviewRerunAndFailClosed(t *testing.T) {
	e := setup(t)
	var calls atomic.Int32
	var bad atomic.Bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls.Add(1)
		for _, private := range []string{"PRIVATE_SOURCE", "profile.name", "localhost", "127.0.0.1", "SYNTHETIC_PRIVATE"} {
			if strings.Contains(string(b), private) {
				t.Errorf("private repair input leaked: %s", private)
			}
		}
		id := "r1"
		if bad.Load() {
			id = "invented"
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": fmt.Sprintf(`{"id":%q}`, id)}}}, "usage": map[string]int{"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}})
	}))
	defer provider.Close()
	client := ai.New("synthetic-provider-key", "fixture")
	client.URL = provider.URL
	client.DailyLimit = 20
	client.TokenLimit = 400000
	h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc, Limits: &api.Limits{}, AI: client})
	if err != nil {
		t.Fatal(err)
	}
	e.api.Close()
	e.api = httptest.NewServer(h)
	t.Cleanup(e.api.Close)
	c := userConfig("repair", e.vendor.URL+"/users")
	c.Name = "PRIVATE_SOURCE"
	f := c.Destination.Mapping["user.name"]
	f.Transform = "integer"
	c.Destination.Mapping["user.name"] = f
	e.save(t, "tenant-a", c, true)
	e.run(t, "tenant-a", c.ID, 200)
	before, err := e.db.Store.ForTenant("tenant-a").Config(context.Background(), c.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	consent := []byte(`{"external_ai_consent":true}`)
	e.request(t, "tenant-b", "POST", "/configs/repair/repair", consent, 404)
	e.request(t, "tenant-a", "POST", "/configs/repair/repair", []byte(`{"external_ai_consent":false}`), 422)
	var response struct {
		Status string    `json:"status"`
		Run    model.Run `json:"run"`
	}
	json.Unmarshal(e.request(t, "tenant-a", "POST", "/configs/repair/repair", consent, 200), &response)
	if response.Status != "repaired_and_rerun" || response.Run.Quarantined != 0 || response.Run.Accepted == 0 || calls.Load() != 1 {
		t.Fatalf("repair %+v calls %d", response, calls.Load())
	}
	after, err := e.db.Store.ForTenant("tenant-a").Config(context.Background(), c.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision <= before.Revision || after.Config.Request.URL != before.Config.Request.URL || after.Config.Destination.Mapping["user.name"].Path == nil || *after.Config.Destination.Mapping["user.name"].Path != *before.Config.Destination.Mapping["user.name"].Path {
		t.Fatal("unsafe mutation")
	}
	var usage store.AIConsumption
	json.Unmarshal(e.request(t, "tenant-a", "GET", "/ai/usage", nil, 200), &usage)
	if usage.Requests != 1 || usage.ReportedTokens != 30 {
		t.Fatal("repair not metered", usage)
	}
	e.request(t, "tenant-a", "POST", "/intel/research", []byte(`{"vendor":"Cisco"}`), 422)
	json.Unmarshal(e.request(t, "tenant-a", "GET", "/ai/usage", nil, 200), &usage)
	if usage.Requests != 1 {
		t.Fatal("unsupported research spent a reservation")
	}
	e.request(t, "tenant-a", "POST", "/configs/repair/repair", consent, 422)
	if calls.Load() != 1 {
		t.Fatal("healthy config spent tokens")
	}
	missing := userConfig("missing", e.vendor.URL+"/users")
	missing.ID = "missing"
	path := "unknown_field"
	f.Path = &path
	missing.Destination.Mapping["user.name"] = f
	e.save(t, "tenant-a", missing, true)
	e.request(t, "tenant-a", "POST", "/configs/missing/repair", consent, 422)
	if calls.Load() != 1 {
		t.Fatal("missing path guessed")
	}
	c.ID = "bad_model"
	e.save(t, "tenant-a", c, true)
	bad.Store(true)
	e.request(t, "tenant-a", "POST", "/configs/bad_model/repair", consent, 502)
	untouched, err := e.db.Store.ForTenant("tenant-a").Config(context.Background(), c.ID, true)
	if err != nil || untouched.Revision != 1 {
		t.Fatal("bad AI changed live config", err)
	}
	// Activation CAS and run pinning reject concurrent revision changes.
	if err = e.db.Store.ForTenant("tenant-a").ActivateExpected(context.Background(), "repair", before.Revision, before.Revision); err != store.ErrBusy {
		t.Fatal("stale activation", err)
	}
	if _, err = e.runs.RunExpected(context.Background(), "tenant-a", "repair", before.Revision); err != store.ErrBusy {
		t.Fatal("stale run", err)
	}
}

func TestResearchMigrationAndSuccessReporting(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	scope := e.db.Store.ForTenant("tenant-a")
	audit := store.AIAudit{RequestID: "research-proof", Actor: "synthetic", SourceID: "public-vendor", Provider: "fixture", Model: "fixture", PromptVersion: "test"}
	if err := scope.ReserveMeteredAI(ctx, 20, 400000, audit, "vendor_intel"); err != nil {
		t.Fatal("vendor migration not applied", err)
	}
	if err := scope.FinishTokens(ctx, audit.RequestID, "researched", insights.Usage{Known: true, Input: 8, Output: 2, Total: 10}); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Summary store.AIReportTotals `json:"summary"`
	}
	json.Unmarshal(e.request(t, "tenant-a", "GET", "/ai/consumption", nil, 200), &report)
	if report.Summary.Requests != 1 || report.Summary.ReportedTokens != 10 || report.Summary.Failed != 0 {
		t.Fatal("successful research marked failed", report)
	}
}
