package ai

import (
	"configbridge/pkg/config"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestReviewedScopesRejectAmbiguousOrUnsupportedRequests(t *testing.T) {
	for _, r := range []Request{
		{Product: "GitHub", Details: "public repository objects"},
		{Product: "GitHub Enterprise"},
		{Product: "GitHub", Profile: "github_repositories"},
		{Product: "CISA", Profile: "github_public_users"},
		{Product: "NVD", Data: "user_inventory"},
	} {
		if e := r.Check(); !errors.Is(e, ErrProfileInput) {
			t.Errorf("%+v: %v", r, e)
		}
	}
}

func TestReviewedDraftsKeepDocumentedContractsDespiteModelGuesses(t *testing.T) {
	for _, tc := range []struct {
		product, id, endpoint, class, auth, paging string
		inputs                                     int
	}{
		{"GitHub", "github_public_users", "https://api.github.com/users", "user_inventory", "bearer", "link", 0},
		{"GitHub", "github_public_contributors", "https://api.github.com/repos/your-owner/your-repo/contributors", "user_inventory", "bearer", "link", 2},
		{"GitHub", "github_public_members", "https://api.github.com/orgs/your-org/public_members", "user_inventory", "bearer", "link", 1},
		{"NVD", "nvd_kev_cves", "https://services.nvd.nist.gov/rest/json/cves/2.0", "vulnerability_finding", "api_key", "offset", 0},
		{"CISA", "cisa_kev", "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json", "vulnerability_finding", "none", "none", 0},
	} {
		t.Run(tc.id, func(t *testing.T) {
			c, seen := fake(t, `{"version":1,"id":"invented_enterprise_config"}`)
			d, e := c.Draft(context.Background(), Request{Product: tc.product, Profile: tc.id, Data: "auto", Details: "PRIVATE_CUSTOMER_NOTES"}, []Secret{{"PRIVATE_SECRET_NAME", "private.internal"}})
			if e != nil {
				t.Fatal(e)
			}
			cfg, issues := config.Decode(d.Config)
			if len(issues) > 0 {
				t.Fatal(issues)
			}
			if cfg.Request.URL != tc.endpoint || cfg.Auth.Type != tc.auth || cfg.Pagination.Type != tc.paging || cfg.Destination.Class != tc.class || cfg.Schedule.Enabled || len(d.Inputs) != tc.inputs {
				t.Fatalf("wrong contract: %s", d.Config)
			}
			if d.Contract == nil || d.Contract.Status != "reviewed_profile_fallback" || len(d.Contract.Fields) == 0 || len(d.Needed) == 0 || len(d.Sources) < 2 {
				t.Fatalf("missing provenance/inputs: %+v", d)
			}
			if len(*seen) != 1 || strings.Contains((*seen)[0], "PRIVATE_") || strings.Contains(string(d.Config), "invented_") {
				t.Fatal("customer metadata disclosed or guessed config accepted")
			}
			if cfg.Auth.Type != "none" && (d.Credential == nil || len(d.Credential.Fields) != 1 || len(d.Credential.Hosts) != 1) {
				t.Fatal("credential inputs missing")
			}
			if tc.product == "NVD" {
				if _, ok := cfg.Request.Params["hasKev"]; !ok {
					t.Fatal("KEV scope lost")
				}
			}
		})
	}
}

func TestReviewedProposalMatchesAndSelectsLocalCredentialWithoutDisclosure(t *testing.T) {
	r := Request{Product: "GitHub", Profile: "github_public_contributors"}
	p, e := selectProfile(r)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := p.configuration()
	if e != nil {
		t.Fatal(e)
	}
	c, seen := fake(t, mustJSON(cfg))
	d, e := c.Draft(context.Background(), r, []Secret{{"CUSTOMER_LOCAL_TOKEN", "api.github.com"}})
	if e != nil {
		t.Fatal(e)
	}
	if d.Contract.Status != "reviewed_profile" || d.Credential.Secret != "CUSTOMER_LOCAL_TOKEN" || strings.Contains((*seen)[0], "CUSTOMER_LOCAL_TOKEN") {
		t.Fatal("reviewed proposal / local credential binding failed")
	}
}
