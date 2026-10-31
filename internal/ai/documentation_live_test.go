package ai

import (
	"configbridge/internal/egress"
	"configbridge/internal/engine"
	"configbridge/pkg/config"
	"configbridge/pkg/mapping"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

// Exercises the same vendor-neutral path used for vendors without reviewed
// examples. Only public documentation is transmitted to the hosted provider.
func TestGenericLiveGithubDocumentation(t *testing.T) {
	if os.Getenv("CB_LIVE_DOCUMENTATION") != "1" {
		t.Skip("opt-in hosted-provider/public-documentation test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 160*time.Second)
	defer cancel()
	c := liveClient(t)
	started := time.Now()
	r := Request{Product: "GitHub", Data: "user_inventory", Dataset: "repository contributors", Scope: "repository", DocumentationURLs: []string{"https://docs.github.com/en/rest/repos/repos#list-repository-contributors"}}
	prepared, e := c.Prepare(ctx, r)
	if e != nil {
		t.Fatal("public reference:", e)
	}
	for _, text := range prepared.documents {
		t.Logf("retrieved public reference excerpt: %d characters", len(text))
	}
	d, e := c.Draft(ctx, prepared, nil)
	if e != nil {
		var bad *InvalidDraft
		if errors.As(e, &bad) {
			t.Logf("validation issues: %+v", bad.Issues)
		}
		t.Fatal("documented draft:", e)
	}
	if d.Contract == nil || d.Contract.Status != "documented_candidate" || len(d.Evidence) < 6 {
		t.Fatal("missing evidence")
	}
	t.Logf("provider=%s model=%s drafting_duration=%s class=%s citations=%d rounds=%d usage_known=%v tokens=%d", c.Provider(), c.ModelID(), time.Since(started).Round(time.Millisecond), d.Data, len(d.Evidence), d.Rounds, d.Usage.Known, d.Usage.Total)
	cfg, issues := config.Decode(d.Config)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	// Fill only local path inputs and collection bounds. Keep the generated
	// auth, pagination and mapping intact when testing the real response.
	cfg.Request.URL = strings.ReplaceAll(strings.ReplaceAll(cfg.Request.URL, "your-owner", "octocat"), "your-repo", "Hello-World")
	if strings.Contains(cfg.Request.URL, "your-") {
		t.Fatal("unfilled path input in generated config")
	}
	if cfg.Auth.Type != "none" && os.Getenv("GITHUB_TOKEN") == "" {
		t.Fatal("GITHUB_TOKEN required to test the generated authenticated config")
	}
	cfg.Limits.MaxPages = 2
	cfg.Limits.MaxRunSeconds = 60
	eng := engine.New(liveCredential{os.Getenv("GITHUB_TOKEN"), "api.github.com"}, egress.Policy{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	accepted, rejected := 0, 0
	res, err := eng.Fetch(ctx, cfg.Connector("generic-live-test"), func(p engine.Page) error {
		for i, row := range p.Items {
			_, bad := mapping.Map(row, cfg, "generic-live-test", time.Now(), i)
			if bad != nil {
				rejected++
				t.Log("mapping rejection", bad.Field, bad.Reason)
			} else {
				accepted++
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, engine.ErrPageLimit) {
		t.Fatal("generated-config collection:", err)
	}
	if accepted == 0 || rejected != 0 {
		t.Fatalf("accepted=%d rejected=%d", accepted, rejected)
	}
	t.Logf("generated config against GitHub: pages=%d accepted=%d rejected=%d bounded=%v", res.Pages, accepted, rejected, errors.Is(err, engine.ErrPageLimit))
}
