package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestParseDiscoveryKeepsOnlySafeLabelledFacts(t *testing.T) {
	d, e := parseDiscovery("Sure!\nURL: https://docs.github.com/en/rest/orgs/members\n- URL: http://insecure.example/x\nURL: https://127.0.0.1/a\nDATASET: List organization members\nSCOPE: Organization\n")
	if e != nil || len(d.urls) != 1 || d.dataset != "List organization members" || d.scope != "organization" {
		t.Fatal(d, e)
	}
	for _, bad := range []string{"URL: none", "URL: https://docs.x.com/a\nSCOPE: public", "URL: https://docs.x.com/a\nDATASET: users\nSCOPE: galaxy"} {
		if _, e := parseDiscovery(bad); !errors.Is(e, ErrDocumentation) {
			t.Fatal("accepted", bad)
		}
	}
}

func TestSameSite(t *testing.T) {
	for _, tc := range []struct {
		api  string
		refs []string
		ok   bool
	}{
		{"https://api.github.com/orgs/x/members", []string{"https://docs.github.com/en/rest"}, true},
		{"https://services.nvd.nist.gov/rest/json/cves/2.0", []string{"https://nvd.nist.gov/developers"}, true},
		{"https://api.example.co.uk/v1", []string{"https://docs.example.co.uk/"}, true},
		{"https://api.example.co.uk/v1", []string{"https://docs.other.co.uk/"}, false},
		{"https://api.github.com/x", []string{"https://github-docs.attacker.example/rest"}, false},
		{"https://your-tenant.okta.com/api/v1/users", []string{"https://anything.example"}, true},
	} {
		if sameSite(tc.api, tc.refs) != tc.ok {
			t.Fatal(tc)
		}
	}
}

func TestNameOnlyNeedsSearchProviderBeforeBudget(t *testing.T) {
	r := Request{Product: "SomeVendor", Data: "auto"}
	if e := r.Check(); e != nil {
		t.Fatal("bare product name must be accepted", e)
	}
	if _, e := New("k", "m").Prepare(context.Background(), r); !errors.Is(e, ErrSearchRequired) {
		t.Fatal("groq cannot search; must refuse before reserving budget", e)
	}
	if _, e := NewGemini("k", "m").Prepare(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	// partial requests still fail closed
	if e := (Request{Product: "SomeVendor", Data: "auto", Dataset: "users"}).Check(); !errors.Is(e, ErrDocumentation) {
		t.Fatal(e)
	}
}

// fakeGemini answers the search call with discovery lines, the draft call with out.
func fakeGemini(t *testing.T, search string, out *modelOutput) (*Client, *[]string) {
	calls := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		text := search
		if strings.Contains(string(b), "google_search") {
			calls = append(calls, "search")
		} else {
			calls = append(calls, "draft")
			text = mustJSON(out)
		}
		json.NewEncoder(w).Encode(map[string]any{"usageMetadata": map[string]int{"promptTokenCount": 10, "totalTokenCount": 30},
			"candidates": []any{map[string]any{"finishReason": "STOP", "content": map[string]any{"parts": []any{map[string]any{"text": text}}}}}})
	}))
	t.Cleanup(srv.Close)
	c := NewGemini("k", "m")
	c.URL, c.HTTP = srv.URL+"/", srv.Client()
	return c, &calls
}

func TestNameOnlyDiscoversVerifiesAndMetersBothCalls(t *testing.T) {
	const ref = "https://docs.github.com/en/rest/orgs/members"
	out, _ := groundedFixture()
	for i := range out.Evidence {
		out.Evidence[i].URL = ref
	}
	c, calls := fakeGemini(t, "URL: "+ref+"\nDATASET: organization members\nSCOPE: organization", out)
	c.FetchDocumentation = func(_ context.Context, u string) (string, error) {
		if u != ref {
			t.Fatal("fetched a page search did not return", u)
		}
		return fixtureDoc, nil
	}
	d, e := c.Draft(context.Background(), Request{Product: "ExampleVendor", Data: "user_inventory"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	// spec search first (finds none), then the documentation search
	if strings.Join(*calls, ",") != "search,search,draft" || d.Contract.Status != "documented_candidate" || len(d.Evidence) == 0 || d.Usage.Total != 90 {
		t.Fatal(*calls, d.Contract, d.Usage)
	}
}

func TestNameOnlySkipsDeadLinksAndFailsWithoutAnyPage(t *testing.T) {
	const dead, live = "https://docs.github.com/dead", "https://docs.github.com/en/rest/orgs/members"
	out, _ := groundedFixture()
	for i := range out.Evidence {
		out.Evidence[i].URL = live
	}
	c, _ := fakeGemini(t, "URL: "+dead+"\nURL: "+live+"\nDATASET: organization members\nSCOPE: organization", out)
	c.FetchDocumentation = func(_ context.Context, u string) (string, error) {
		if u == dead {
			return "", ErrDocumentation
		}
		return fixtureDoc, nil
	}
	d, e := c.Draft(context.Background(), Request{Product: "ExampleVendor", Data: "user_inventory"}, nil)
	if e != nil || len(d.Sources) != 1 || d.Sources[0] != live {
		t.Fatal("dead link not skipped", d, e)
	}
	c, calls := fakeGemini(t, "DATASET: organization members\nSCOPE: organization", out) // no URL, no grounding
	if _, e = c.Draft(context.Background(), Request{Product: "ExampleVendor", Data: "user_inventory"}, nil); !errors.Is(e, ErrDocumentation) || len(*calls) != 2 {
		t.Fatal("drafted without any real reference", e, *calls)
	}
}

func TestNameOnlyRejectsAPIOnAnotherSiteThanTheDocs(t *testing.T) {
	out, _ := groundedFixture() // config calls api.github.com, docs live on vendor.example
	c, _ := fakeGemini(t, "URL: "+fixtureReference+"\nDATASET: organization members\nSCOPE: organization", out)
	c.FetchDocumentation = func(context.Context, string) (string, error) { return fixtureDoc, nil }
	_, e := c.Draft(context.Background(), Request{Product: "ExampleVendor", Data: "user_inventory"}, nil)
	var bad *InvalidDraft
	if !errors.As(e, &bad) || bad.Issues[0].Field != "request.url" || bad.Last != nil {
		t.Fatal("lookalike documentation accepted", e)
	}
}

// Live: CB_LIVE_DISCOVERY=1 GEMINI_API_KEY=... CB_AI_MODEL=gemini-3.5-flash
// LIVE_PRODUCTS="Okta;FIRST EPSS" go test -v -run TestLiveNameOnly ./internal/ai
func TestLiveNameOnly(t *testing.T) {
	if os.Getenv("CB_LIVE_DISCOVERY") != "1" || os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("set CB_LIVE_DISCOVERY=1 and GEMINI_API_KEY")
	}
	c := NewGemini(os.Getenv("GEMINI_API_KEY"), os.Getenv("CB_AI_MODEL"))
	c.Resolve = LookupDNS
	for _, p := range strings.Split(os.Getenv("LIVE_PRODUCTS"), ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		t.Run(p, func(t *testing.T) {
			c.debugDiscovery = func(s string) { t.Logf("SEARCH %q", s) }
			d, e := c.Draft(context.Background(), Request{Product: p, Data: "auto"}, nil)
			var bad *InvalidDraft
			switch {
			case errors.As(e, &bad):
				t.Logf("REJECTED tokens=%d issues=%v", bad.Usage.Total, bad.Issues)
			case e != nil:
				t.Logf("FAILED %v", e)
			default:
				t.Logf("DRAFTED class=%s endpoint=%s auth=%s paging=%s sources=%v credential=%v tokens=%d evidence=%d",
					d.Data, d.Contract.Endpoint, d.Contract.Auth, d.Contract.Pagination, d.Sources, d.Credential, d.Usage.Total, len(d.Evidence))
			}
		})
	}
}
