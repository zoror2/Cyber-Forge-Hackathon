package tests

import (
	"bytes"
	"configbridge/configs"
	"configbridge/internal/api"
	"configbridge/internal/egress"
	"configbridge/internal/engine"
	"configbridge/internal/runner"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Opt-in proof with real vendor credentials, production egress/TLS, the real
// mapper/API and isolated Docker PostgreSQL. No AI is configured. testutil
// removes only this test's schema and runtime role when it finishes.
func TestLiveThreeSourcesThroughAPIAndPostgresWithoutAI(t *testing.T) {
	if os.Getenv("CB_LIVE_SOURCES") != "1" {
		t.Skip("opt-in real vendor collection")
	}
	if os.Getenv("GITHUB_TOKEN") == "" || os.Getenv("NVD_API_KEY") == "" {
		t.Fatal("vendor credentials required")
	}
	e := setup(t)
	eng := engine.New(e.svc, egress.Policy{}, e.requests.Log)
	e.runs = runner.New(e.db.Store, eng)
	h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc, Limits: &api.Limits{}})
	if err != nil {
		t.Fatal(err)
	}
	e.api.Close()
	e.api = httptest.NewServer(h)
	defer e.api.Close()
	for _, tc := range []struct {
		name                string
		raw                 []byte
		endpoint, env, host string
	}{
		{"GitHub", configs.GitHubMembers, "https://api.github.com/repos/octocat/Hello-World/contributors", "GITHUB_TOKEN", "api.github.com"},
		{"NVD", configs.NVDKEVCVEs, "", "NVD_API_KEY", "services.nvd.nist.gov"},
		{"CISA", configs.CISAKEV, "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, issues := config.Decode(tc.raw)
			if len(issues) > 0 {
				t.Fatal(issues)
			}
			if tc.endpoint != "" {
				cfg.Request.URL = tc.endpoint
			}
			cfg.Schedule.Enabled = false
			if tc.name == "GitHub" {
				cfg.ID = "public_repo_contributors"
				cfg.Name = "Public repository contributors"
				cfg.Request.Headers["X-GitHub-Api-Version"] = "2026-03-10"
				cfg.Request.Params["per_page"] = "2"
			}
			if tc.env != "" {
				body, _ := json.Marshal(map[string]string{"value": os.Getenv(tc.env), "allowed_host": tc.host})
				e.request(t, "tenant-a", "PUT", "/secrets/"+cfg.Auth.Secret, body, 204)
			}
			e.save(t, "tenant-a", cfg, true)
			var first int
			for attempt := 0; attempt < 2; attempt++ {
				run := e.run(t, "tenant-a", cfg.ID, 200)
				if run.Outcome != "success" || run.Accepted == 0 || run.Quarantined != 0 {
					t.Fatal("live collection did not complete cleanly", run.Outcome, run.Accepted, run.Quarantined, run.Error)
				}
				var count int
				err = e.db.Store.ForTenant("tenant-a").WithTx(context.Background(), func(tx pgx.Tx) error {
					return tx.QueryRow(context.Background(), "SELECT count(*) FROM ocsf_records WHERE source=$1", cfg.ID).Scan(&count)
				})
				if err != nil {
					t.Fatal(err)
				}
				if attempt == 0 {
					first = count
				} else if count != first {
					t.Fatal("re-run created duplicates or source changed during test", first, count)
				}
				t.Logf("%s collection=%d pages=%d received=%d accepted=%d quarantined=%d stored=%d outcome=%s", tc.name, attempt+1, run.Pages, run.Received, run.Accepted, run.Quarantined, count, run.Outcome)
			}
		})
	}
	var other []any
	json.Unmarshal(e.request(t, "tenant-b", "GET", "/records/user_inventory", nil, 200), &other)
	if len(other) > 0 {
		t.Fatal("cross-tenant records exposed")
	}
	for _, env := range []string{"GITHUB_TOKEN", "NVD_API_KEY"} {
		if bytes.Contains([]byte(e.logs.String()), []byte(os.Getenv(env))) {
			t.Fatal("credential value appeared in logs")
		}
	}
}
