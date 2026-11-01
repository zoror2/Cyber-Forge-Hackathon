package ai

import (
	"context"
	"strings"
	"testing"
)

func TestEmbeddedSpecsReadMeAndRedoc(t *testing.T) {
	spec := `{"openapi":"3.1.0","servers":[{"url":"https://cloud.vendor.example"}],"paths":{"/vulns":{"get":{"summary":"List vulnerabilities","responses":{"200":{"content":{"application/json":{"schema":{"type":"object","properties":{"vulnerabilities":{"type":"array","items":{"type":"object","properties":{"plugin_id":{"type":"integer"}}}}}}}}}}}}}}`
	for name, page := range map[string]string{
		"readme": `<html><script id="ssr-props" type="application/x-ssr-props">{"document":{"api":{"schema":` + spec + `}}}</script></html>`,
		"redoc":  `<html><script>const __redoc_state = {"spec":{"data":` + spec + `}};</script></html>`,
	} {
		got := embeddedSpecs("https://developer.vendor.example/ref", page)
		if len(got) != 1 || len(got[0].listOps()) != 1 || got[0].servers[0] != "https://cloud.vendor.example" {
			t.Fatal(name, got)
		}
	}
	if len(embeddedSpecs("https://x.example", `<script>var paths = "x"</script>`)) != 0 {
		t.Fatal("non-spec script accepted")
	}
}

func TestServerVariablesMatchTemplateOrDefaults(t *testing.T) {
	got := serverVariants("https://api.meraki.com/{basePath}", map[string]any{"basePath": map[string]any{"default": "api/v1"}})
	if !contains(got, "https://api.meraki.com/api/v1") {
		t.Fatal(got)
	}
	got = serverVariants("https://{subdomain}.{site}", map[string]any{"subdomain": map[string]any{"default": "api"}, "site": map[string]any{"default": "datadoghq.com"}})
	if !contains(got, "https://api.datadoghq.com") || !contains(got, "https://{subdomain}.{site}") {
		t.Fatal(got)
	}
}

func TestStaticHeaderFormatMustBeStatedBySpec(t *testing.T) {
	r, _ := acmeRequest(t)
	ok := strings.Replace(acmeConfig, `{"type":"api_key","secret":"acme_token","header":"Authorization"}`,
		`{"type":"static","secret":"acme_token","headers":[{"name":"Authorization","value":"SSWS {{secret.value}}"}]}`, 1)
	if issues, _ := verifySpec(r, mustDecode(t, ok)); len(issues) != 0 {
		t.Fatal("documented SSWS prefix rejected", issues)
	}
	bad := strings.Replace(ok, "SSWS ", "Token ", 1)
	if issues, _ := verifySpec(r, mustDecode(t, bad)); len(issues) == 0 {
		t.Fatal("invented header prefix accepted")
	}
}

func TestSuppliedSpecTextNeedsNoSearch(t *testing.T) {
	c, calls := specGemini(t, "GET /api/v1/users")
	r := Request{Product: "Acme", Data: "auto", SpecURL: acmeSpecURL, SpecText: acmeSpec}
	if e := r.Check(); e != nil {
		t.Fatal(e)
	}
	d, e := c.Draft(context.Background(), r, nil)
	if e != nil || strings.Join(*calls, ",") != "pick,draft" || !strings.Contains(d.Notes[0], "you supplied") {
		t.Fatal(e, *calls)
	}
	if e := (Request{Product: "Acme", Data: "auto", SpecText: "x", DocumentationURLs: []string{acmeSpecURL}}).Check(); e == nil {
		t.Fatal("spec plus docs accepted")
	}
	if _, e := New("k", "m").Prepare(context.Background(), r); e != nil {
		t.Fatal("supplied spec must not need web search", e)
	}
}

func TestCombinedAPIKeyHeaders(t *testing.T) {
	spec := strings.Replace(acmeSpec, "    apiToken: {type: apiKey, in: header, name: Authorization, description: SSWS token}",
		"    apiToken: {type: apiKey, in: header, name: Authorization, description: SSWS token}\n    apiKeyAuth: {type: apiKey, in: header, name: DD-API-KEY}\n    appKeyAuth: {type: apiKey, in: header, name: DD-APPLICATION-KEY}", 1)
	spec = strings.Replace(spec, "security:\n  - apiToken: []", "security:\n  - apiKeyAuth: []\n    appKeyAuth: []", 1)
	sp, e := parseSpec(acmeSpecURL, spec)
	if e != nil {
		t.Fatal(e)
	}
	r := Request{Scope: "organization", spec: &specRef{sp, sp.ops["GET /api/v1/users"]}}
	both := strings.Replace(acmeConfig, `{"type":"api_key","secret":"acme_token","header":"Authorization"}`,
		`{"type":"static","secret":"dd","headers":[{"name":"DD-API-KEY","value":"{{secret.api_key}}"},{"name":"DD-APPLICATION-KEY","value":"{{secret.app_key}}"}]}`, 1)
	if issues, _ := verifySpec(r, mustDecode(t, both)); len(issues) != 0 {
		t.Fatal(issues)
	}
	one := strings.Replace(both, `,{"name":"DD-APPLICATION-KEY","value":"{{secret.app_key}}"}`, "", 1)
	if issues, _ := verifySpec(r, mustDecode(t, one)); len(issues) == 0 {
		t.Fatal("half of a combined requirement accepted")
	}
}

func TestRegistryNames(t *testing.T) {
	if reviewedSpec("Jira Cloud") != atlassianJira || reviewedSpec("Tenable Vulnerability Management") != tenableVulns || reviewedSpec("SonicWall") != "" {
		t.Fatal("registry lookup")
	}
}
