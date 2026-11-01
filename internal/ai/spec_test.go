package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"configbridge/pkg/config"
)

// YAML on purpose: unquoted 200 keys, $ref parameters, allOf.
const acmeSpecURL = "https://developer.acme.com/openapi.yaml"
const acmeSpec = `openapi: 3.0.1
servers:
  - url: https://{yourDomain}.acme.com
paths:
  /api/v1/users:
    get:
      summary: List all users
      tags: [User]
      parameters:
        - name: limit
          in: query
          schema: {type: integer}
        - name: filter
          in: query
          schema: {type: string, enum: [active, suspended]}
        - $ref: '#/components/parameters/after'
      responses:
        200:
          description: ok
          headers:
            link: {schema: {type: string}}
          content:
            application/json:
              schema:
                type: array
                items: {$ref: '#/components/schemas/User'}
  /api/v1/users/{id}:
    get:
      summary: Get a user
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses:
        200: {content: {application/json: {schema: {$ref: '#/components/schemas/User'}}}}
components:
  parameters:
    after: {name: after, in: query, schema: {type: string}}
  securitySchemes:
    apiToken: {type: apiKey, in: header, name: Authorization, description: SSWS token}
  schemas:
    User:
      type: object
      properties:
        id: {type: string}
        profile:
          allOf:
            - $ref: '#/components/schemas/Profile'
    Profile:
      type: object
      properties:
        email: {type: string, format: email}
security:
  - apiToken: []
`

const acmeConfig = `{"version":1,"id":"acme_users","name":"Acme users","vendor":"Acme",
"request":{"method":"GET","url":"https://your-tenant.acme.com/api/v1/users","timeout_seconds":20,"params":{"limit":"200"}},
"auth":{"type":"api_key","secret":"acme_token","header":"Authorization"},
"items_path":"","pagination":{"type":"link"},
"schedule":{"enabled":false,"interval_seconds":3600},
"destination":{"class":"user_inventory","mapping":{
 "user.uid":{"path":"id","required":true,"transform":"string"},
 "user.email_addr":{"path":"profile.email"},
 "metadata.product.name":{"constant":"Acme"}}},
"limits":{"max_pages":10,"max_records":500,"max_response_bytes":1048576,"max_run_seconds":60},
"retry":{"max_attempts":3,"base_delay_ms":1000,"max_retry_after_seconds":60}}`

func acmeRequest(t *testing.T) (Request, *apiSpec) {
	sp, e := parseSpec(acmeSpecURL, acmeSpec)
	if e != nil {
		t.Fatal(e)
	}
	return Request{Product: "Acme", Data: "user_inventory", Dataset: "List all users", Scope: "organization", spec: &specRef{sp, sp.ops["GET /api/v1/users"]}}, sp
}

func TestParseSpecYAMLRefsAndCatalog(t *testing.T) {
	_, sp := acmeRequest(t)
	cat, listed := sp.catalog()
	if len(listed) != 1 || !strings.Contains(cat, "GET /api/v1/users | List all users | User") {
		t.Fatal("single-item operation listed or list missing:", cat)
	}
	x := sp.excerpt(sp.ops["GET /api/v1/users"])
	for _, want := range []string{`apiToken: apiKey in header "Authorization"`, "- profile.email: string (email)", `RECORDS at items_path ""`, "- after (query, string, optional)", "one of: active, suspended", "RESPONSE HEADERS: link"} {
		if !strings.Contains(x, want) {
			t.Fatalf("excerpt lacks %q:\n%s", want, x)
		}
	}
	if _, e := parseSpec("https://x.example/a.json", `{"hello":"world"}`); !errors.Is(e, errNotSpec) {
		t.Fatal("non-spec accepted")
	}
}

func TestSwagger2JSONSpec(t *testing.T) {
	sp, e := parseSpec("https://docs.vendor.example/swagger.json", `{"swagger":"2.0","host":"api.vendor.example","basePath":"/v2",
	"securityDefinitions":{"b":{"type":"basic"}},
	"paths":{"/alerts":{"get":{"summary":"List alerts","parameters":[{"name":"page","in":"query","type":"integer"},{"name":"per_page","in":"query","type":"integer"}],
	"responses":{"200":{"schema":{"type":"object","properties":{"data":{"type":"array","items":{"type":"object","properties":{"uuid":{"type":"string"}}}},"next":{"type":"string"}}}}}}}}}`)
	if e != nil {
		t.Fatal(e)
	}
	op := sp.ops["GET /alerts"]
	if strings.Join(sp.collections(op.response), ",") != "data" || sp.servers[0] != "https://api.vendor.example/v2" {
		t.Fatal(sp.servers, sp.collections(op.response))
	}
	cfg := mustDecode(t, strings.NewReplacer(`https://your-tenant.acme.com/api/v1/users`, `https://api.vendor.example/v2/alerts`, `"params":{"limit":"200"}`, `"params":{}`,
		`{"type":"api_key","secret":"acme_token","header":"Authorization"}`, `{"type":"basic","secret":"v","username":"me"}`,
		`"items_path":""`, `"items_path":"data"`, `{"type":"link"}`, `{"type":"page","page_param":"page","size_param":"per_page","page_size":50}`,
		`"user_inventory"`, `"detection_finding"`, `"user.uid":{"path":"id","required":true,"transform":"string"},
 "user.email_addr":{"path":"profile.email"},`, `"finding_info.uid":{"path":"uuid","required":true},"finding_info.title":{"path":"uuid"},`).Replace(acmeConfig))
	r := Request{spec: &specRef{sp, op}, Scope: "account"}
	if issues, _ := verifySpec(r, cfg); len(issues) != 0 {
		t.Fatal(issues)
	}
}

func mustDecode(t *testing.T, raw string) config.Config {
	cfg, issues := config.Decode([]byte(raw))
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	return cfg
}

func TestVerifySpecAcceptsOnlyWhatTheSpecDeclares(t *testing.T) {
	r, _ := acmeRequest(t)
	issues, ev := verifySpec(r, mustDecode(t, acmeConfig))
	if len(issues) != 0 || len(ev) < 6 {
		t.Fatal(issues, ev)
	}
	for name, bad := range map[string][2]string{
		"undeclared param":   {`"params":{"limit":"200"}`, `"params":{"status":"x"}`},
		"enum value":         {`"params":{"limit":"200"}`, `"params":{"filter":"deleted"}`},
		"other path":         {`/api/v1/users"`, `/api/v1/accounts"`},
		"literal path param": {`/api/v1/users"`, `/api/v1/users/00u1"`},
		"other host":         {`your-tenant.acme.com`, `api.evil.example`},
		"wrong header":       {`"header":"Authorization"`, `"header":"X-Api-Key"`},
		"invented field":     {`"profile.email"`, `"profile.phone"`},
		"wrong items_path":   {`"items_path":""`, `"items_path":"data"`},
		"undeclared cursor":  {`{"type":"link"}`, `{"type":"cursor","cursor_param":"after","cursor_path":"next","page_size":10}`},
		"bearer not offered": {`{"type":"api_key","secret":"acme_token","header":"Authorization"}`, `{"type":"bearer","secret":"acme_token"}`},
	} {
		raw := strings.Replace(acmeConfig, bad[0], bad[1], 1)
		cfg, decodeIssues := config.Decode([]byte(raw))
		if len(decodeIssues) != 0 {
			t.Fatal(name, decodeIssues)
		}
		if issues, _ := verifySpec(r, cfg); len(issues) == 0 {
			t.Fatal("accepted:", name)
		}
	}
}

func TestSpecTrusted(t *testing.T) {
	for _, tc := range []struct {
		spec, api string
		ok        bool
	}{
		{"https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json", "https://your-tenant.atlassian.net/rest/api/3/users/search", true},
		{"https://raw.githubusercontent.com/okta/okta-management-openapi-spec/master/x.yaml", "https://your-tenant.okta.com/api/v1/logs", true},
		{"https://raw.githubusercontent.com/attacker/okta-spec/main/x.yaml", "https://your-tenant.okta.com/api/v1/logs", false},
		{"https://developer.acme.com/openapi.yaml", "https://api.evil.example/v1", false},
		{"https://developer.acme.com/openapi.yaml", "https://your-tenant/api/v1/users", true},
	} {
		if specTrusted(tc.spec, tc.api) != tc.ok {
			t.Fatal(tc)
		}
	}
}

// specGemini fakes the spec search, the operation pick and the draft.
func specGemini(t *testing.T, pick string) (*Client, *[]string) {
	calls := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var text string
		switch body := string(b); {
		case strings.Contains(body, "OpenAPI (Swagger) specification"):
			calls, text = append(calls, "spec"), "SPEC: "+acmeSpecURL
		case strings.Contains(body, "google_search"):
			calls, text = append(calls, "search"), "URL: none"
		case strings.Contains(body, "OPERATION CATALOG"):
			calls, text = append(calls, "pick"), mustJSON(map[string]any{"operation": pick, "class": "user_inventory", "scope": "organization", "alternatives": []string{"GET /nope"}, "reason": "lists users"})
		default:
			if strings.Contains(body, "PRIVATE") {
				t.Error("private data sent to model")
			}
			calls, text = append(calls, "draft"), mustJSON(modelOutput{ConfigJSON: acmeConfig, Plan: "standard"})
		}
		json.NewEncoder(w).Encode(map[string]any{"usageMetadata": map[string]int{"promptTokenCount": 10, "totalTokenCount": 30},
			"candidates": []any{map[string]any{"finishReason": "STOP", "content": map[string]any{"parts": []any{map[string]any{"text": text}}}}}})
	}))
	t.Cleanup(srv.Close)
	c := NewGemini("k", "m")
	c.URL, c.HTTP = srv.URL+"/", srv.Client()
	c.FetchSpec = func(_ context.Context, u string) (string, error) {
		if u != acmeSpecURL {
			t.Fatal("fetched a spec search did not return", u)
		}
		return acmeSpec, nil
	}
	return c, &calls
}

func TestNameOnlyDraftsFromOpenAPISpec(t *testing.T) {
	c, calls := specGemini(t, "GET /api/v1/users")
	d, e := c.Draft(context.Background(), Request{Product: "Acme", Data: "auto"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Join(*calls, ",") != "spec,pick,draft" || d.Contract.Profile != "openapi_vendor" || d.Contract.Scope != "List all users (organization)" ||
		len(d.Evidence) == 0 || d.Sources[0] != acmeSpecURL || d.Usage.Total != 90 || d.Credential == nil {
		t.Fatal(*calls, d.Contract, d.Sources, d.Usage)
	}
}

func TestPickOutsideTheCatalogFallsBackToDocsNotToTheModel(t *testing.T) {
	c, calls := specGemini(t, "GET /api/v1/admins")
	_, e := c.Draft(context.Background(), Request{Product: "Acme", Data: "auto"}, nil)
	if !errors.Is(e, ErrDocumentation) || strings.Join(*calls, ",") != "spec,pick,search" {
		t.Fatal("invented operation reached drafting", e, *calls)
	}
}
