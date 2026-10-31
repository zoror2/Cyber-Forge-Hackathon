package tests

import (
	"configbridge/internal/egress"
	"configbridge/internal/engine"
	"configbridge/internal/runner"
	"configbridge/pkg/config"
	"configbridge/pkg/ocsf"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
)

// These tests require real accounts. Missing credentials fail an explicitly
// selected live test; they are never converted into a vendor compatibility pass.
// Vendor calls are read-only, AI is absent, and data lives in a disposable DB.
func TestVendorLiveEngineAndStorage(t *testing.T) {
	selected := os.Getenv("CB_VENDOR_LIVE")
	if selected == "" {
		t.Skip("select elastic, sophos or trellix with CB_VENDOR_LIVE; live sandbox required")
	}
	var file, endpoint, secret string
	fields := map[string]string{}
	require := func(name string) string {
		t.Helper()
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("live test blocked: missing private environment variable %s", name)
		}
		return v
	}
	base := func(name string) *url.URL {
		t.Helper()
		u, err := url.Parse(require(name))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			t.Fatalf("%s must be an HTTPS API origin, not a dashboard/path/query URL", name)
		}
		return u
	}
	switch selected {
	case "elastic":
		file = "elastic_security_alerts.json"
		secret = "elastic_security"
		u := base("CB_TEST_ELASTIC_URL")
		space := require("CB_TEST_ELASTIC_SPACE")
		if strings.ContainsAny(space, "/\\?#%") {
			t.Fatal("invalid Elastic space ID")
		}
		u.Path = "/.alerts-security.alerts-" + space + "/_search"
		endpoint = u.String()
		fields["value"] = require("CB_TEST_ELASTIC_API_KEY")
	case "sophos":
		file = "sophos_central_endpoints.json"
		secret = "sophos_central"
		u := base("CB_TEST_SOPHOS_API_URL")
		u.Path = "/endpoint/v1/endpoints"
		endpoint = u.String()
		fields["client_id"] = require("CB_TEST_SOPHOS_CLIENT_ID")
		fields["client_secret"] = require("CB_TEST_SOPHOS_CLIENT_SECRET")
		require("CB_TEST_SOPHOS_TENANT_ID")
	case "trellix":
		file = "trellix_edr_alerts.json"
		secret = "trellix_edr"
		u := base("CB_TEST_TRELLIX_API_URL")
		u.Path = "/edr/v2/alerts"
		endpoint = u.String()
		fields["access_token"] = require("CB_TEST_TRELLIX_ACCESS_TOKEN")
		fields["api_key"] = require("CB_TEST_TRELLIX_API_KEY")
	default:
		t.Fatal("no reviewed live test for selected vendor; see docs/VENDOR_TESTING.md")
	}
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Fatal("TEST_DATABASE_URL required; use disposable Docker PostgreSQL")
	}
	raw, err := os.ReadFile("../configs/" + file)
	if err != nil {
		t.Fatal(err)
	}
	cfg, issues := config.Decode(raw)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	cfg.Request.URL = endpoint
	cfg.Limits.MaxPages = 2
	cfg.Limits.MaxRecords = 200
	cfg.Schedule.Enabled = false
	if selected == "sophos" {
		cfg.Request.Headers["X-Tenant-ID"] = os.Getenv("CB_TEST_SOPHOS_TENANT_ID")
	}
	u, _ := url.Parse(endpoint)
	hosts := []string{u.Host}
	if cfg.Auth.TokenURL != "" {
		tokenURL, _ := url.Parse(cfg.Auth.TokenURL)
		if tokenURL.Host != u.Host {
			hosts = append(hosts, tokenURL.Host)
		}
	}
	e := setup(t)
	productionEngine := engine.New(e.svc, egress.Policy{}, e.requests.Log)
	runs := runner.New(e.db.Store, productionEngine)
	body, _ := json.Marshal(map[string]any{"fields": fields, "allowed_hosts": hosts})
	e.request(t, "tenant-a", "PUT", "/secrets/"+secret, body, 204)
	revision := e.save(t, "tenant-a", cfg, true)
	ctx := context.Background()
	preview, err := runs.Preview(ctx, "tenant-a", cfg.ID, revision)
	if err != nil || preview.Accepted < 1 || preview.Quarantined != 0 {
		t.Fatal("live preview failed/empty/invalid records", preview, err)
	}
	class, _ := ocsf.Lookup(cfg.Destination.Class)
	before, err := e.db.Store.ForTenant("tenant-a").Records(ctx, class.UID, cfg.ID, 100, 0)
	if err != nil || len(before) != 0 {
		t.Fatal("preview persisted records", err)
	}
	run, err := runs.Run(ctx, "tenant-a", cfg.ID, false, false)
	bounded := errors.Is(err, engine.ErrPageLimit) || errors.Is(err, runner.ErrLimit)
	if err != nil && !bounded {
		t.Fatal("live collection failed", run, err)
	}
	if run.Accepted < 1 || run.Quarantined != 0 {
		t.Fatal("live mapping failed/empty", run)
	}
	stored, err := e.db.Store.ForTenant("tenant-a").Records(ctx, class.UID, cfg.ID, 500, 0)
	if err != nil || len(stored) != run.Accepted {
		t.Fatal("stored count mismatch", len(stored), run, err)
	}
	other, err := e.db.Store.ForTenant("tenant-b").Records(ctx, class.UID, "", 500, 0)
	if err != nil || len(other) != 0 {
		t.Fatal("tenant leak", err)
	}
	for _, value := range fields {
		if strings.Contains(e.logs.String(), value) {
			t.Fatal("credential leaked")
		}
	}
	t.Logf("vendor=%s pages=%d accepted=%d quarantined=%d outcome=%s bounded_sample=%v; this is not proof of an unbounded full sync", selected, run.Pages, run.Accepted, run.Quarantined, run.Outcome, bounded)
}
