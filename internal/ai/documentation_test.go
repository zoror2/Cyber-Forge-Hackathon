package ai

import (
	"configbridge/configs"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const fixtureReference = "https://docs.vendor.example/users"
const fixtureExample = `[{"id":1,"login":"demo","site_admin":false}]`
const fixtureDoc = "Public organization members. GET /orgs/owasp/members . API base https://api.github.com . Authentication: Bearer . Link pagination uses the Link header. per_page query parameter. " + fixtureExample

func groundedFixture() (*modelOutput, Request) {
	evidence := []Evidence{{"dataset", "organization members", fixtureReference, "Public organization members"}, {"query_param", "per_page", fixtureReference, "per_page query parameter"}}
	for _, e := range []Evidence{{"endpoint", "https://api.github.com/orgs/owasp/members", fixtureReference, "Public organization members. GET /orgs/owasp/members"}, {"api_host", "api.github.com", fixtureReference, "API base https://api.github.com"}, {"auth", "bearer", fixtureReference, "Authentication: Bearer"}, {"scope", "organization", fixtureReference, "Public organization members"}, {"pagination", "link", fixtureReference, "Link pagination uses the Link header"}, {"items_path", "", fixtureReference, fixtureExample}, {"field", "id", fixtureReference, fixtureExample}, {"field", "login", fixtureReference, fixtureExample}, {"field", "site_admin", fixtureReference, fixtureExample}} {
		evidence = append(evidence, e)
	}
	return &modelOutput{ConfigJSON: string(configs.GitHubMembers), Evidence: evidence, Plan: "standard", Sources: []string{"https://invented.invalid/pricing"}, Needed: []string{"invented enterprise subscription"}}, Request{Product: "ExampleVendor", Data: "user_inventory", Dataset: "organization members", Scope: "organization", Details: "PRIVATE_CUSTOMER_NOTES", DocumentationURLs: []string{fixtureReference}}
}
func TestGenericDraftUsesRetrievedEvidenceAndKeepsPrivateContextLocal(t *testing.T) {
	for _, product := range []string{"ExampleVendor", "AnotherVendor", "GitHub Enterprise"} {
		t.Run(product, func(t *testing.T) {
			out, r := groundedFixture()
			r.Product = product
			requests := []string{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				b, _ := io.ReadAll(req.Body)
				requests = append(requests, string(b))
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": mustJSON(out)}}}, "usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}})
			}))
			defer srv.Close()
			c := New("fixture", "fixture")
			c.URL = srv.URL
			c.FetchDocumentation = func(_ context.Context, u string) (string, error) {
				if u != fixtureReference {
					t.Fatal(u)
				}
				return fixtureDoc, nil
			}
			if e := r.Check(); e != nil {
				t.Fatal(e)
			}
			d, e := c.Draft(context.Background(), r, []Secret{{"PRIVATE_SECRET_NAME", "private.internal"}})
			if e != nil {
				t.Fatal(e)
			}
			if d.Contract == nil || d.Contract.Status != "documented_candidate" || d.Sources[0] != fixtureReference || len(d.Evidence) == 0 || !d.Usage.Known || d.Usage.Total != 30 {
				t.Fatal("missing proof/usage", d)
			}
			if len(requests) != 1 || strings.Contains(requests[0], "PRIVATE_") || !strings.Contains(requests[0], "documented_connector_draft") {
				t.Fatal("private context disclosed or citation schema missing")
			}
		})
	}
}
func TestGenericVerificationRejectsWrongRouteFieldsAndFabricatedCitations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*modelOutput, *Request)
	}{
		{"wrong endpoint", func(o *modelOutput, r *Request) {
			o.ConfigJSON = strings.ReplaceAll(o.ConfigJSON, "/orgs/owasp/members", "/enterprises/invented/members")
		}},
		{"invented response field", func(o *modelOutput, r *Request) {
			o.ConfigJSON = strings.ReplaceAll(o.ConfigJSON, `"login"`, `"made_up_email"`)
		}},
		{"fabricated source", func(o *modelOutput, r *Request) { o.Evidence[0].URL = "https://invented.invalid" }},
		{"undocumented authentication", func(o *modelOutput, r *Request) {
			o.ConfigJSON = strings.ReplaceAll(o.ConfigJSON, `"type":"bearer"`, `"type":"basic","username":"u"`)
		}},
		{"wrong dataset scope", func(o *modelOutput, r *Request) { r.Scope = "repository" }},
		{"different requested dataset", func(o *modelOutput, r *Request) { r.Dataset = "repository objects" }},
		{"unsolicited premium", func(o *modelOutput, r *Request) { o.Plan = "premium" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, r := groundedFixture()
			tc.change(o, &r)
			r.documents = map[string]string{fixtureReference: fixtureDoc}
			cfg, is := config.Decode([]byte(o.ConfigJSON))
			if len(is) > 0 {
				t.Fatal("test candidate not syntactically valid", is)
			}
			if got := verifyDocumentation(r, cfg, o); len(got) == 0 {
				t.Fatal("unsupported execution contract accepted")
			}
		})
	}
}

// Misquoted or missing model excerpts are not fatal when the fetched page
// itself states every configured fact; the platform reads the page.
func TestPageProvesFactsWhenModelMisquotes(t *testing.T) {
	o, r := groundedFixture()
	for i := range o.Evidence {
		o.Evidence[i].Quote = "paraphrased, not on the page"
	}
	r.documents = map[string]string{fixtureReference: fixtureDoc}
	cfg, _ := config.Decode([]byte(o.ConfigJSON))
	if got := verifyDocumentation(r, cfg, o); len(got) != 0 {
		t.Fatal(got)
	}
	r.documents = map[string]string{fixtureReference: strings.Replace(fixtureDoc, "Bearer", "token", 1)}
	if got := verifyDocumentation(r, cfg, o); len(got) == 0 {
		t.Fatal("auth absent from the page must still fail")
	}
}

func TestRelativeRouteNeedsItsBaseURLOnThePage(t *testing.T) {
	o, r := groundedFixture()
	o.ConfigJSON = strings.ReplaceAll(o.ConfigJSON, "https://api.github.com/orgs/owasp/members", "https://api.github.com/v3/orgs/owasp/members")
	cfg, _ := config.Decode([]byte(o.ConfigJSON))
	r.documents = map[string]string{fixtureReference: fixtureDoc} // no ".../v3" base on the page
	if got := verifyDocumentation(r, cfg, o); len(got) == 0 {
		t.Fatal("route prefix accepted without its documented base URL")
	}
	r.documents = map[string]string{fixtureReference: fixtureDoc + " Base URL: https://api.github.com/v3 ."}
	if got := verifyDocumentation(r, cfg, o); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestGenericFailsClosedBeforeAnyModelCall(t *testing.T) {
	c := New("fixture", "fixture")
	c.URL = "http://127.0.0.1:1"
	_, r := groundedFixture()
	r.DocumentationURLs = nil
	if e := r.Check(); !errors.Is(e, ErrDocumentation) {
		t.Fatal(e)
	}
	if _, e := c.Draft(context.Background(), r, nil); !errors.Is(e, ErrDocumentation) {
		t.Fatal(e)
	}
	r.Product = "GitHub"
	if _, e := c.Draft(context.Background(), r, nil); !errors.Is(e, ErrDocumentation) {
		t.Fatal("known example silently replaced an explicit dataset", e)
	}
	r.Product = "ExampleVendor"
	for _, raw := range []string{"http://docs.example.com", "https://user:password@docs.example.com", "https://docs.example.com?api_key=secret", "https://docs.example.com:8443/api"} {
		r.DocumentationURLs = []string{raw}
		if r.Check() == nil {
			t.Fatal("unsafe URL accepted", raw)
		}
	}
	r.DocumentationURLs = []string{fixtureReference}
	c.FetchDocumentation = func(context.Context, string) (string, error) { return "", ErrDocumentation }
	if _, e := c.Draft(context.Background(), r, nil); !errors.Is(e, ErrDocumentation) {
		t.Fatal(e)
	}
}
func TestGenericDoesNotReturnExecutableCandidateAfterEvidenceFailures(t *testing.T) {
	c, seen := fake(t, string(configs.GitHubMembers))
	_, r := groundedFixture()
	// the page does not state the auth scheme, so verification must fail
	c.FetchDocumentation = func(context.Context, string) (string, error) {
		return strings.Replace(fixtureDoc, "Authentication: Bearer", "", 1), nil
	}
	d, e := c.Draft(context.Background(), r, nil)
	var invalid *InvalidDraft
	if d != nil || !errors.As(e, &invalid) || invalid.Last != nil || len(invalid.Issues) == 0 || len(*seen) != 1+MaxRepairs {
		t.Fatal("unguarded candidate exposed", d, e)
	}
}

func TestPublicDocumentationReaderRejectsInternalDestinations(t *testing.T) {
	for _, raw := range []string{"https://127.0.0.1/api", "https://169.254.169.254/metadata", "https://[::1]/api", "file:///etc/passwd"} {
		if _, e := readPublicDocumentation(context.Background(), raw); !errors.Is(e, ErrDocumentation) {
			t.Fatal("unsafe document destination accepted", raw, e)
		}
	}
}
func TestFocusedDocumentationKeepsOnlyChosenOperation(t *testing.T) {
	body := `<h2 id="wrong">Enterprise pricing</h2><h2 id="right">Public users</h2><h3>Auth</h3>Bearer<h2 id="next">Other endpoint</h2>`
	got := focusedSection(body, "right")
	if !strings.Contains(got, "Public users") || !strings.Contains(got, "Bearer") || strings.Contains(got, "Enterprise") || strings.Contains(got, "Other endpoint") {
		t.Fatal(got)
	}
	if focusedSection(body, "absent") != body {
		t.Fatal("missing headings must not invent a section")
	}
}

func TestDocumentationHandlesHighlightedRoutesAndCanonicalEvidenceLabels(t *testing.T) {
	out, r := groundedFixture()
	doc := strings.ReplaceAll(fixtureDoc, "GET /orgs/owasp/members", "GET /orgs /owasp /members")
	r.documents = map[string]string{fixtureReference + "#operation": doc}
	for i := range out.Evidence {
		if out.Evidence[i].Kind == "endpoint" {
			out.Evidence[i].Quote = "Public organization members. GET /orgs /owasp /members"
		}
		if out.Evidence[i].Kind == "api_host" {
			out.Evidence[i].Value = "https://api.github.com"
		}
	}
	cfg, is := config.Decode([]byte(out.ConfigJSON))
	if len(is) > 0 {
		t.Fatal(is)
	}
	if issues := verifyDocumentation(r, cfg, out); len(issues) > 0 {
		t.Fatal(issues)
	}
	for _, e := range out.Evidence {
		if e.URL != fixtureReference+"#operation" {
			t.Fatal("citation lost its retrieved section", e)
		}
	}
	out, r = groundedFixture()
	r.documents = map[string]string{fixtureReference: strings.ReplaceAll(fixtureDoc, "/orgs/owasp/members", "/orgs/owasp/members-extra")}
	for i := range out.Evidence {
		if out.Evidence[i].Kind == "endpoint" {
			out.Evidence[i].Quote = "Public organization members. GET /orgs/owasp/members-extra"
		}
	}
	if issues := verifyDocumentation(r, cfg, out); len(issues) == 0 {
		t.Fatal("endpoint-prefix confusion accepted")
	}
}

func TestDocumentationRejectsHostAndRouteSubstringConfusion(t *testing.T) {
	for _, tc := range []struct{ old, replacement string }{
		{"https://api.github.com", "https://api.github.com.attacker.example"},
		{"GET /orgs/owasp/members", "GET /other/orgs/owasp/members"},
	} {
		out, r := groundedFixture()
		r.documents = map[string]string{fixtureReference: strings.ReplaceAll(fixtureDoc, tc.old, tc.replacement)}
		for i := range out.Evidence {
			out.Evidence[i].Quote = strings.ReplaceAll(out.Evidence[i].Quote, tc.old, tc.replacement)
		}
		cfg, issues := config.Decode([]byte(out.ConfigJSON))
		if len(issues) != 0 {
			t.Fatal(issues)
		}
		if len(verifyDocumentation(r, cfg, out)) == 0 {
			t.Fatal("substring mistaken for exact host/route evidence")
		}
	}
}
