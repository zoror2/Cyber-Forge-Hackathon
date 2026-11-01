package tests

import (
	"configbridge/internal/api"
	"configbridge/internal/insights"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

type findingSearch struct {
	mode    string
	mu      sync.Mutex
	indexed []byte
}

func (s *findingSearch) Index(_ context.Context, _ string, snap insights.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.indexed, _ = json.Marshal(snap)
	if s.mode == "offline" {
		return insights.ErrSearch
	}
	return nil
}
func (s *findingSearch) Find(_ context.Context, _ string, snap insights.Snapshot, topic string) ([]string, error) {
	out := []string{}
	for _, f := range snap.Findings {
		r, _ := insights.RuleByID(f.Rule)
		if r.Topic == topic {
			out = append(out, f.ID)
		}
	}
	switch s.mode {
	case "foreign":
		return []string{insights.Hash("tenant-b")}, nil
	case "missing":
		return []string{}, nil
	case "duplicate":
		if len(out) > 0 {
			out = append(out, out[0])
		}
	}
	return out, nil
}

type explanationProvider struct {
	calls    int
	evidence insights.Evidence
	bad      bool
	unknown  bool
	err      error
}

func (p *explanationProvider) Provider() string { return "fixture" }
func (p *explanationProvider) ModelID() string  { return "fixture" }
func (p *explanationProvider) Explain(_ context.Context, e insights.Evidence) (insights.Answer, insights.Usage, error) {
	p.calls++
	p.evidence = e
	u := insights.Usage{Known: !p.unknown, Input: 100, Output: 20, Total: 120}
	a := insights.Answer{Summary: "Review the reported findings; their cause is not established.", EvidenceIDs: []string{"e1"}, NextChecks: []string{"event_review"}}
	if p.bad {
		a.EvidenceIDs = []string{"not-present"}
	}
	return a, u, p.err
}
func siemAPI(t *testing.T, e *environment, s insights.Search, p *explanationProvider) {
	t.Helper()
	h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc, Limits: &api.Limits{}, SIEM: &api.SIEM{Search: s, Provider: p, EnabledTenants: map[string]bool{"tenant-a": true, "tenant-b": true}, DailyCalls: 20, DailyTokens: 400000}})
	if err != nil {
		t.Fatal(err)
	}
	e.api.Close()
	e.api = httptest.NewServer(h)
	t.Cleanup(e.api.Close)
}
func securityConfig(t *testing.T, e *environment, id string) config.Config {
	t.Helper()
	raw, err := os.ReadFile("../configs/mock_security_events.json")
	if err != nil {
		t.Fatal(err)
	}
	c, issues := config.Decode(raw)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	c.ID = id
	c.Name = "PRIVATE_CUSTOMER_NAME"
	c.Request.URL = e.vendor.URL + "/security-events"
	c.Request.AllowedPorts = []int{portOf(e.vendor.URL)}
	return c
}
func question(id, topic string) []byte {
	b, _ := json.Marshal(api.SIEMQuestion{Connector: id, Topic: topic, Consent: true})
	return b
}
func TestSIEMRulesPrivacyUsageAndConsole(t *testing.T) {
	e := setup(t)
	search := &findingSearch{}
	p := &explanationProvider{}
	siemAPI(t, e, search, p)
	c := securityConfig(t, e, "private_source")
	e.save(t, "tenant-a", c, true)
	if r := e.run(t, "tenant-a", c.ID, 200); r.Accepted != 9 {
		t.Fatal(r)
	}
	var snap insights.Snapshot
	b, _ := json.Marshal(map[string]string{"connector": c.ID})
	if err := json.Unmarshal(e.request(t, "tenant-a", "POST", "/siem/refresh", b, 200), &snap); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int64{}
	for _, f := range snap.Findings {
		counts[f.Rule] = f.Count
	}
	if counts["authentication_failures"] != 6 || counts["high_severity_events"] != 1 {
		t.Fatal("event-time rules incorrect", counts)
	}
	var response api.SIEMResponse
	if err := json.Unmarshal(e.request(t, "tenant-a", "POST", "/siem/ask", question(c.ID, "security_findings"), 200), &response); err != nil {
		t.Fatal(err)
	}
	if p.calls != 1 || response.Status != "explanation_requires_review" || !response.Usage.Known {
		t.Fatal(response)
	}
	raw, _ := json.Marshal(p.evidence)
	for _, private := range []string{"private_source", "tenant-a", "PRIVATE_CUSTOMER_NAME", "SYNTHETIC_PRIVATE_DESCRIPTION", "user@example.invalid", "192.0.2.1", key("tenant-a")} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private data entered prompt")
		}
	}
	var usage store.AIConsumption
	if err := json.Unmarshal(e.request(t, "tenant-a", "GET", "/ai/usage", nil, 200), &usage); err != nil || usage.ReportedTokens != 120 || usage.UnreportedReserved != 0 || usage.Requests != 1 {
		t.Fatal("usage", usage, err)
	}
	var other store.AIConsumption
	json.Unmarshal(e.request(t, "tenant-b", "GET", "/ai/usage", nil, 200), &other)
	if other.Requests != 0 {
		t.Fatal("usage crossed tenant")
	}
	e.request(t, "tenant-b", "POST", "/siem/ask", question(c.ID, "security_findings"), 404)
	e.request(t, "tenant-b", "GET", "/siem/findings?connector="+c.ID, nil, 404)
	for _, body := range []string{`{"connector":"private_source","topic":"security_findings","external_ai_consent":true,"tenant_id":"tenant-b"}`} {
		e.request(t, "tenant-a", "POST", "/siem/ask", []byte(body), 400)
	}
	e.request(t, "tenant-a", "POST", "/siem/ask", []byte(`{"connector":"private_source","topic":"security_findings"}`), 422)
	e.request(t, "tenant-a", "GET", "/siem/findings?connector=bad!", nil, 422)
	// the latest snapshot is readable without another AI call
	var stored insights.Snapshot
	if err := json.Unmarshal(e.request(t, "tenant-a", "GET", "/siem/findings?connector="+c.ID, nil, 200), &stored); err != nil || len(stored.Findings) == 0 {
		t.Fatal("findings", err)
	}
	// Healthy collection yields no operational findings and costs no AI call.
	before := p.calls
	e.request(t, "tenant-a", "POST", "/siem/ask", question(c.ID, "connection_health"), 200)
	if p.calls != before {
		t.Fatal("empty findings called AI")
	}
}
func TestSIEMRejectsBadSearchAndProviderResults(t *testing.T) {
	for _, mode := range []string{"offline", "foreign", "missing", "duplicate", "bad_answer", "provider_error", "unknown_usage"} {
		t.Run(mode, func(t *testing.T) {
			e := setup(t)
			search := &findingSearch{mode: mode}
			p := &explanationProvider{bad: mode == "bad_answer", unknown: mode == "unknown_usage"}
			if mode == "provider_error" {
				p.err = errors.New("PRIVATE_PROVIDER_ERROR")
			}
			siemAPI(t, e, search, p)
			c := securityConfig(t, e, "events")
			e.save(t, "tenant-a", c, true)
			e.run(t, "tenant-a", c.ID, 200)
			want := 503
			if mode == "unknown_usage" {
				want = 200
			}
			out := e.request(t, "tenant-a", "POST", "/siem/ask", question(c.ID, "security_findings"), want)
			if strings.Contains(string(out), "PRIVATE_PROVIDER_ERROR") {
				t.Fatal("error leak")
			}
			if mode == "offline" || mode == "foreign" || mode == "missing" || mode == "duplicate" {
				if p.calls != 0 {
					t.Fatal("untrusted retrieval reached AI")
				}
			}
			if mode == "unknown_usage" {
				usage, err := e.db.Store.ForTenant("tenant-a").AIConsumption(context.Background())
				if err != nil || usage.UnreportedReserved != store.AIReservation || usage.ReportedTokens != 0 {
					t.Fatal("unknown treated as zero", usage, err)
				}
			}
		})
	}
}
func TestSIEMCollectionFailuresRecoveryAndCanonicalFencing(t *testing.T) {
	e := setup(t)
	search := &findingSearch{}
	p := &explanationProvider{}
	siemAPI(t, e, search, p)
	c := userConfig("failing", e.vendor.URL+"/flaky")
	c.Request.Params = map[string]string{"scenario_id": "siem_fail", "fail": "100"}
	c.Retry.MaxAttempts = 1
	e.save(t, "tenant-a", c, true)
	for i := 0; i < 3; i++ {
		e.run(t, "tenant-a", c.ID, 502)
	}
	e.request(t, "tenant-a", "POST", "/siem/ask", question(c.ID, "connection_health"), 200)
	if p.evidence.Facts[0].Rule != "collection_failures" || p.evidence.Facts[0].Count != 3 {
		t.Fatal(p.evidence)
	}
	scope := e.db.Store.ForTenant("tenant-a")
	old, err := scope.SIEMSnapshot(context.Background(), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.Request.URL = e.vendor.URL + "/users"
	c.Request.Params = nil
	e.save(t, "tenant-a", c, true)
	e.run(t, "tenant-a", c.ID, 200)
	e.request(t, "tenant-a", "POST", "/siem/ask", question(c.ID, "connection_health"), 200)
	if p.calls != 1 {
		t.Fatal("recovered finding replayed")
	}
	if _, err = scope.ResolveSIEM(context.Background(), c.ID, old.Generation, []string{old.Findings[0].ID}, "connection_health"); err == nil {
		t.Fatal("stale snapshot accepted")
	}
	if err = scope.WithTx(context.Background(), func(tx pgx.Tx) error {
		var n int
		err := tx.QueryRow(context.Background(), "SELECT count(*) FROM siem_snapshots WHERE tenant_id='tenant-b'").Scan(&n)
		if n != 0 {
			t.Fatal("RLS bypass")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
func TestSIEMRealOpenSearch(t *testing.T) {
	endpoint := os.Getenv("TEST_OPENSEARCH_URL")
	if endpoint == "" {
		t.Skip("TEST_OPENSEARCH_URL required for Docker OpenSearch integration")
	}
	e := setup(t)
	search, err := insights.NewSearch(endpoint, "", "", "dev", e.db.Schema, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := &explanationProvider{}
	siemAPI(t, e, search, p)
	c := securityConfig(t, e, "events")
	e.save(t, "tenant-a", c, true)
	e.run(t, "tenant-a", c.ID, 200)
	e.request(t, "tenant-a", "POST", "/siem/ask", question(c.ID, "security_findings"), 200)
	// The same connector ID in another tenant has different records and index.
	c.Request.URL = e.vendor.URL + "/users"
	c.Destination = userConfig("events", c.Request.URL).Destination
	e.save(t, "tenant-b", c, true)
	e.run(t, "tenant-b", c.ID, 200)
	e.request(t, "tenant-b", "POST", "/siem/ask", question(c.ID, "security_findings"), 200)
	if p.calls != 1 {
		t.Fatal("tenant B saw tenant A search findings")
	}
}
