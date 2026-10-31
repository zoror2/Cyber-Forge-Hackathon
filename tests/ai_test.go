package tests

import (
	"bytes"
	"configbridge/internal/aidraft"
	"configbridge/internal/api"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const userDraftPlan = `{"items_path":"","pagination":{"type":"page","page_param":"page","size_param":"per_page","page_size":10,"start_page":1},"mapping":{"id":{"path":"id","transform":"string"},"name":{"path":"login","transform":"string"}}}`

type draftProvider struct {
	calls  atomic.Int32
	output string
	err    error
}

func (p *draftProvider) Name() string  { return "mock-groq" }
func (p *draftProvider) Model() string { return "fixture" }
func (p *draftProvider) Generate(_ context.Context, s aidraft.Source) ([]byte, error) {
	p.calls.Add(1)
	return []byte(p.output), p.err
}
func draftAPI(t *testing.T, e *environment, p aidraft.Provider, limit int) *api.Drafting {
	t.Helper()
	sources, err := aidraft.LoadSources("../public_sources")
	if err != nil {
		t.Fatal(err)
	}
	d := &api.Drafting{Provider: p, Sources: sources, EnabledTenants: map[string]bool{"tenant-a": true}, DailyLimit: limit}
	h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc, AI: d})
	if err != nil {
		t.Fatal(err)
	}
	e.api.Close()
	e.api = httptest.NewServer(h)
	t.Cleanup(e.api.Close)
	return d
}
func TestAIDraftReviewPreviewAndTenantPrivacy(t *testing.T) {
	e := setup(t)
	p := &draftProvider{output: userDraftPlan}
	draftAPI(t, e, p, 2)
	e.request(t, "tenant-b", "GET", "/ai/sources", nil, 503)
	e.request(t, "tenant-a", "GET", "/ai/sources", nil, 200)
	for _, body := range []string{
		`{"source_id":"github_members","connector_id":"draft","external_ai_consent":true,"credential":"PRIVATE-SENTINEL"}`,
		`{"source_id":"github_members","connector_id":"draft","external_ai_consent":true,"sample_records":[{"email":"PRIVATE-SENTINEL"}]}`,
		`{"source_id":"github_members","connector_id":"draft","external_ai_consent":true,"documentation":"PRIVATE-SENTINEL"}`,
		`{"source_id":"github_members","connector_id":"draft","external_ai_consent":true,"tenant_id":"tenant-b"}`,
	} {
		e.request(t, "tenant-a", "POST", "/ai/config-draft", []byte(body), 400)
	}
	e.request(t, "tenant-a", "POST", "/ai/config-draft", []byte(`{"source_id":"github_members","connector_id":"draft"}`), 422)
	e.request(t, "tenant-a", "POST", "/ai/config-draft", []byte(`{"source_id":"missing","connector_id":"draft","external_ai_consent":true}`), 404)
	e.request(t, "tenant-b", "POST", "/ai/config-draft", []byte(`{"source_id":"github_members","connector_id":"draft","external_ai_consent":true}`), 503)
	if p.calls.Load() != 0 {
		t.Fatal("provider called before consent or validation")
	}
	body := []byte(`{"source_id":"github_members","connector_id":"customer_private_id","name":"PRIVATE-CUSTOMER-SENTINEL","external_ai_consent":true}`)
	out := e.request(t, "tenant-a", "POST", "/ai/config-draft", body, 200)
	var proposal struct {
		Status string        `json:"status"`
		Review bool          `json:"review_required"`
		Config config.Config `json:"config"`
	}
	if err := json.Unmarshal(out, &proposal); err != nil {
		t.Fatal(err)
	}
	if proposal.Status != "draft_proposal" || !proposal.Review || proposal.Config.Schedule.Enabled || proposal.Config.Name != "PRIVATE-CUSTOMER-SENTINEL" {
		t.Fatal("unsafe draft")
	}
	if _, err := e.db.Store.ForTenant("tenant-a").Config(context.Background(), proposal.Config.ID, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("AI persisted a config")
	}
	audits := e.request(t, "tenant-a", "GET", "/ai/audit", nil, 200)
	if bytes.Contains(audits, []byte("PRIVATE-CUSTOMER-SENTINEL")) || bytes.Contains(audits, []byte("customer_private_id")) || !bytes.Contains(audits, []byte("draft_validated")) {
		t.Fatal("audit privacy or completeness", string(audits))
	}
	if string(e.request(t, "tenant-b", "GET", "/ai/audit", nil, 200)) != "[]\n" {
		t.Fatal("cross-tenant audit")
	}
	// Customer fills the local connection details only after receiving the draft.
	c := proposal.Config
	c.Request.URL = e.vendor.URL + "/users"
	c.Request.AllowedPorts = []int{portOf(e.vendor.URL)}
	// The TLS fixture uses a different nested shape; the customer reviews/edits it.
	path := "profile.name"
	field := c.Destination.Mapping["name"]
	field.Path = &path
	c.Destination.Mapping["name"] = field
	c.Auth.Type = "none"
	c.Auth.Secret = ""
	raw, _ := json.Marshal(c)
	saved := e.request(t, "tenant-a", "POST", "/configs", raw, 201)
	var revision struct {
		Revision int `json:"revision"`
	}
	if err := json.Unmarshal(saved, &revision); err != nil {
		t.Fatal(err)
	}
	e.request(t, "tenant-a", "POST", "/connectors/"+c.ID+"/run", nil, 404)
	previewBody, _ := json.Marshal(map[string]int{"revision": revision.Revision})
	preview := e.request(t, "tenant-a", "POST", "/configs/"+c.ID+"/test", previewBody, 200)
	if !bytes.Contains(preview, []byte(`"mode":"test"`)) || !bytes.Contains(preview, []byte(`"accepted":10`)) {
		t.Fatal(string(preview))
	}
	for _, table := range []string{"users", "runs", "quarantine", "sync_state"} {
		err := e.db.Store.ForTenant("tenant-a").WithTx(context.Background(), func(tx pgx.Tx) error {
			var n int
			err := tx.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n)
			if n != 0 {
				t.Fatal("preview wrote " + table)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	e.request(t, "tenant-b", "POST", "/configs/"+c.ID+"/test", previewBody, 404)
	e.request(t, "tenant-a", "POST", "/configs/"+c.ID+"/test", []byte(`{"revision":999}`), 404)
	e.request(t, "tenant-a", "POST", "/configs/"+c.ID+"/test", []byte(`{"revision":0}`), 400)
	e.request(t, "tenant-a", "POST", "/configs/"+c.ID+"/activate", previewBody, 200)
	if result := e.run(t, "tenant-a", c.ID, 200); result.Accepted != 25 {
		t.Fatal(result)
	}
	e.request(t, "tenant-a", "POST", "/ai/config-draft", body, 200)
	e.request(t, "tenant-a", "POST", "/ai/config-draft", body, 429)
	if p.calls.Load() != 2 {
		t.Fatal("budget failed", p.calls.Load())
	}
	err := e.db.Store.ForTenant("tenant-a").WithTx(context.Background(), func(tx pgx.Tx) error { _, err := tx.Exec(context.Background(), "DELETE FROM ai_audit"); return err })
	if err == nil {
		t.Fatal("runtime could delete audit")
	}
}
func TestAIFailuresAreAuditedAndBounded(t *testing.T) {
	for _, test := range []struct {
		name, output string
		err          error
		want         int
	}{{"provider failure", "", errors.New("PRIVATE-PROVIDER-TEXT"), 502}, {"bad JSON", "not JSON", nil, 422}, {"injection", strings.Replace(userDraftPlan, `"items_path":""`, `"url":"https://evil.example","items_path":""`, 1), nil, 422}} {
		t.Run(test.name, func(t *testing.T) {
			e := setup(t)
			p := &draftProvider{output: test.output, err: test.err}
			draftAPI(t, e, p, 1)
			body := []byte(`{"source_id":"github_members","connector_id":"draft","external_ai_consent":true}`)
			out := e.request(t, "tenant-a", "POST", "/ai/config-draft", body, test.want)
			if bytes.Contains(out, []byte("PRIVATE-PROVIDER-TEXT")) {
				t.Fatal("provider text leaked")
			}
			e.request(t, "tenant-a", "POST", "/ai/config-draft", body, 429)
			if p.calls.Load() != 1 {
				t.Fatal("failed call did not count")
			}
			var audit []store.AIAudit
			if err := json.Unmarshal(e.request(t, "tenant-a", "GET", "/ai/audit", nil, 200), &audit); err != nil || len(audit) != 2 {
				t.Fatal("missing audit", err, len(audit))
			}
		})
	}
}
