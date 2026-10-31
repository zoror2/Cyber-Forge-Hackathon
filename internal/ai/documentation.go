package ai

import (
	"configbridge/internal/egress"
	"configbridge/pkg/config"
	"configbridge/pkg/mapping"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var ErrDocumentation = errors.New("official_documentation_required: provide public API documentation URLs, the requested dataset and scope; no endpoint or mapping will be guessed")

// Evidence connects an execution setting to a literal excerpt of a document
// that the backend actually retrieved. This proves presence in that reference,
// not that the publisher is trustworthy or that the customer's access works.
type Evidence struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	URL   string `json:"url"`
	Quote string `json:"quote"`
}

func (r Request) checkDocumentation() error {
	if len(r.DocumentationURLs) < 1 || len(r.DocumentationURLs) > 3 || len(strings.TrimSpace(r.Dataset)) < 2 || len(r.Dataset) > 200 {
		return ErrDocumentation
	}
	switch r.Scope {
	case "public", "repository", "organization", "account", "enterprise":
	default:
		return ErrDocumentation
	}
	for _, raw := range r.DocumentationURLs {
		if !publicDocURL(raw) {
			return fmt.Errorf("%w: links must be public HTTPS documentation without credentials, query parameters or nonstandard ports", ErrDocumentation)
		}
	}
	return nil
}
func publicDocURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && len(raw) <= 2000 && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && (u.Port() == "" || u.Port() == "443") && !strings.Contains(u.Host, "your-") && (egress.Policy{}).CheckURL(u) == nil
}

var scriptTags = regexp.MustCompile(`(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)>`)
var markupTags = regexp.MustCompile(`<[^>]+>`)
var documentationSlots = make(chan struct{}, 4)

const maxDocumentationBytes = 8 << 20

// maxDocumentationText bounds the excerpt sent to the model per reference.
// API references put auth, paging and response examples far down the page;
// 6000 characters cut them off, so evidence checks failed on real vendors.
const maxDocumentationText = 40000

func compact(s string) string { return strings.Join(strings.Fields(s), " ") }
func readPublicDocumentation(ctx context.Context, raw string) (string, error) {
	if !publicDocURL(raw) {
		return "", ErrDocumentation
	}
	u, _ := url.Parse(raw)
	fragment := u.Fragment
	u.Fragment = ""
	b, contentType, e := fetchPublic(ctx, u, "text/html, text/plain, application/json", maxDocumentationBytes)
	if e != nil {
		return "", e
	}
	text := string(b)
	if strings.Contains(contentType, "html") {
		if fragment != "" {
			text = focusedSection(text, fragment)
		}
		text = html.UnescapeString(markupTags.ReplaceAllString(scriptTags.ReplaceAllString(text, " "), " "))
	}
	text = compact(text)
	if len(text) < 20 {
		return "", fmt.Errorf("%w: page has no usable public API text", ErrDocumentation)
	}
	// Bound prompt size as well as download size. Evidence can only cite the
	// transmitted excerpt; a later section needs a more focused reference.
	if len(text) > maxDocumentationText {
		text = strings.Clone(text[:maxDocumentationText])
	}
	return text, nil
}

// fetchPublic downloads one public HTTPS reference: egress guarded, no
// redirects, bounded in time, concurrency and size. Shared by documentation
// pages and OpenAPI specs.
func fetchPublic(ctx context.Context, u *url.URL, accept string, limit int) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	select {
	case documentationSlots <- struct{}{}:
		defer func() { <-documentationSlots }()
	case <-ctx.Done():
		return nil, "", fmt.Errorf("%w: documentation reader busy", ErrDocumentation)
	}
	client := (egress.Policy{}).Client(15 * time.Second)
	defer client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if e != nil {
		return nil, "", ErrDocumentation
	}
	req.Header.Set("Accept", accept)
	res, e := client.Do(req)
	if e != nil {
		return nil, "", fmt.Errorf("%w: public documentation could not be reached", ErrDocumentation)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, "", fmt.Errorf("%w: documentation returned HTTP %d; provide its final public URL", ErrDocumentation, res.StatusCode)
	}
	contentType := strings.ToLower(res.Header.Get("Content-Type"))
	if !strings.Contains(contentType, "text/") && !strings.Contains(contentType, "json") && !strings.Contains(contentType, "yaml") {
		return nil, "", fmt.Errorf("%w: use a text, HTML, JSON or YAML reference", ErrDocumentation)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, int64(limit)+1))
	if e != nil || len(b) > limit {
		return nil, "", fmt.Errorf("%w: document unavailable or larger than %d MiB", ErrDocumentation, limit>>20)
	}
	return b, contentType, nil
}

// A supplied heading fragment focuses a large API reference on the operation
// the customer chose. It is a document selection, never an inferred API route.
func focusedSection(body, fragment string) string {
	re := regexp.MustCompile(`(?i)<h([1-6])\b[^>]*\bid=["']` + regexp.QuoteMeta(fragment) + `["'][^>]*>`)
	m := re.FindStringSubmatchIndex(body)
	if m == nil {
		return body
	}
	start := m[0]
	level := body[m[2]:m[3]]
	next := regexp.MustCompile(`(?i)<h` + level + `\b`).FindStringIndex(body[m[1]:])
	if next == nil {
		return body[start:]
	}
	return body[start : m[1]+next[0]]
}

// Prepare retrieves public references before reserving paid AI tokens.
func (c *Client) Prepare(ctx context.Context, r Request) (Request, error) {
	if len(r.DocumentationURLs) == 0 {
		// name-only needs web search; refuse before any budget is reserved
		if p, _ := selectProfile(r); p == nil && r.nameOnly() && !c.gemini {
			return r, ErrSearchRequired
		}
		return r, nil
	}
	if e := r.checkDocumentation(); e != nil {
		return r, e
	}
	if r.documents != nil {
		return r, nil
	}
	r.documents = map[string]string{}
	for _, source := range r.DocumentationURLs {
		fetch := c.FetchDocumentation
		if fetch == nil {
			fetch = readPublicDocumentation
		}
		text, e := fetch(ctx, source)
		if e != nil {
			return r, e
		}
		text = compact(text)
		if len(text) > maxDocumentationText {
			text = strings.Clone(text[:maxDocumentationText])
		}
		r.documents[source] = text
	}
	return r, nil
}
func (c *Client) documentedDraft(ctx context.Context, r Request) (*Draft, error) {
	r, e := c.Prepare(ctx, r)
	if e != nil {
		return nil, e
	}
	// Never send private free-text notes, stored-secret metadata, owner/repo
	// inputs or collected records to the hosted model.
	safe := Request{Product: r.Product, Data: r.Data, Dataset: r.Dataset, Scope: r.Scope, documents: r.documents}
	for _, source := range r.DocumentationURLs {
		safe.Details += "\nPUBLIC REFERENCE " + source + "\n" + r.documents[source] + "\nEND REFERENCE\n"
	}
	return c.generate(ctx, safe, nil)
}

func documentedSchema() schema {
	props := map[string]any{}
	for k, v := range outputSchema["properties"].(map[string]any) {
		props[k] = v
	}
	props["evidence"] = map[string]any{"type": "array", "items": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"kind", "value", "url", "quote"}, "properties": map[string]any{
		"kind":  map[string]any{"type": "string", "enum": []string{"endpoint", "api_host", "auth", "token_url", "items_path", "pagination", "field", "scope", "dataset", "query_param"}},
		"value": map[string]any{"type": "string", "description": "Exact configured URL, hostname, auth type, collection path, pagination type, mapped response path, or requested scope."},
		"url":   map[string]any{"type": "string", "description": "An attached public reference URL."},
		"quote": map[string]any{"type": "string", "description": "Literal excerpt from that reference. Endpoint: documented route; auth: scheme and header; fields/items_path: a valid JSON response example containing that exact path; pagination: documented strategy/parameter names; scope: access scope."},
	}}}
	required := append([]string{}, outputSchema["required"].([]string)...)
	required = append(required, "evidence")
	return schema{"documented_connector_draft", "Draft with exact evidence from the supplied public documentation", map[string]any{"type": "object", "additionalProperties": false, "required": required, "properties": props}}
}

var pathTemplate = regexp.MustCompile(`\{[^}]+\}|your-[a-zA-Z0-9_-]+`)
var slashSpacing = regexp.MustCompile(`\s*/\s*`)

func route(s string) string { return pathTemplate.ReplaceAllString(s, "{}") }
func jsonExample(quote string) (any, bool) {
	quote = strings.TrimSpace(quote)
	var v any
	if json.Unmarshal([]byte(quote), &v) == nil {
		return v, true
	}
	for _, brackets := range [][2]string{{"{", "}"}, {"[", "]"}} {
		a, b := strings.Index(quote, brackets[0]), strings.LastIndex(quote, brackets[1])
		if a >= 0 && b > a && json.Unmarshal([]byte(quote[a:b+1]), &v) == nil {
			return v, true
		}
	}
	return nil, false
}
func examplePath(v any, path string) bool {
	if _, ok := mapping.Path(v, path); ok {
		return true
	}
	if rows, ok := v.([]any); ok && len(rows) > 0 {
		_, ok = mapping.Path(rows[0], path)
		return ok
	}
	return false
}
func verifyDocumentation(r Request, cfg config.Config, out *modelOutput) []config.Issue {
	var issues []config.Issue
	problem := func(field, msg string) { issues = append(issues, config.Issue{Field: field, Message: msg}) }
	by := map[string][]Evidence{}
	canonicalURL := func(raw string) string {
		u, e := url.Parse(raw)
		if e != nil {
			return ""
		}
		u.Fragment = ""
		return u.String()
	}
	for _, e := range out.Evidence {
		q := compact(e.Quote)
		if len(q) < 4 || len(q) > 4000 {
			continue
		}
		for source, doc := range r.documents {
			if canonicalURL(source) == canonicalURL(e.URL) && strings.Contains(doc, q) {
				e.URL = source
				by[e.Kind] = append(by[e.Kind], e)
				break
			}
		}
	}
	checked := []Evidence{}
	proven := func(kind, value string, predicate func(string) bool) bool {
		// Verify against the actual config, not the model's spelling of its
		// evidence label (e.g. hostname versus https://hostname).
		for _, e := range by[kind] {
			if predicate(e.Quote) {
				e.Value = value
				checked = append(checked, e)
				return true
			}
		}
		return false
	}
	u, _ := url.Parse(cfg.Request.URL)
	if !proven("endpoint", cfg.Request.URL, func(q string) bool {
		// Syntax-highlight spans can add spaces around route slashes during
		// HTML text extraction. Normalize those separators, preserving the
		// exact route and an ending boundary (not a prefix of another route).
		q = slashSpacing.ReplaceAllString(q, "/")
		path := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(cfg.Request.Method) + `\s*` + regexp.QuoteMeta(route(u.Path)) + `(?:[\s?\x22'\\),\]]|$)`)
		return path.MatchString(route(q)) && strings.Contains(strings.ToLower(q), strings.ToLower(r.Dataset))
	}) {
		problem("request.url", "cite one literal excerpt containing the requested dataset heading, HTTP method and exact endpoint path; no replacement URL will be guessed")
	}
	host := regexp.MustCompile(`(?i)https://` + regexp.QuoteMeta(u.Hostname()) + `(?:[/:\s\x22'\\),\]]|$)`)
	if !proven("api_host", u.Hostname(), func(q string) bool { return host.MatchString(q) }) {
		problem("request.url", "API hostname needs a literal public-reference citation")
	}
	for name := range cfg.Request.Params {
		if !proven("query_param", name, func(q string) bool { return strings.Contains(q, name) }) {
			problem("request.params."+name, "query parameter needs a public-reference citation")
		}
	}
	if !proven("scope", r.Scope, func(q string) bool { return strings.Contains(strings.ToLower(q), r.Scope) }) {
		problem("scope", "reference does not establish the selected scope; clarify the dataset rather than substituting another one")
	}
	if !proven("dataset", r.Dataset, func(q string) bool { return strings.Contains(strings.ToLower(q), strings.ToLower(r.Dataset)) }) {
		problem("dataset", "cite the explicitly requested dataset; another dataset cannot be substituted")
	}
	if r.Scope != "enterprise" && (out.Plan == "premium" || strings.Contains(strings.ToLower(u.Path), "/enterprises/")) {
		problem("scope", "Enterprise/premium data was not requested")
	}
	if !proven("auth", cfg.Auth.Type, func(q string) bool {
		q = strings.ToLower(q)
		switch cfg.Auth.Type {
		case "none":
			return strings.Contains(q, "no authentication") || strings.Contains(q, "unauthenticated") || strings.Contains(q, "without authentication") || strings.Contains(q, "does not require authentication")
		case "bearer":
			return strings.Contains(q, "bearer")
		case "basic":
			return strings.Contains(q, "basic")
		case "api_key":
			return strings.Contains(q, strings.ToLower(cfg.Auth.Header))
		case "oauth2_client_credentials":
			return strings.Contains(q, "client_credentials")
		case "static":
			for _, h := range cfg.Auth.Headers {
				prefix := strings.ToLower(strings.TrimSpace(strings.Split(h.Value, "{{")[0]))
				if prefix != "" && !strings.Contains(q, prefix) {
					return false
				}
			}
			return strings.Contains(q, "authorization")
		}
		return false
	}) {
		problem("auth", "authentication scheme/header needs evidence from the public reference")
	}
	if cfg.Auth.TokenURL != "" && !proven("token_url", cfg.Auth.TokenURL, func(q string) bool { return strings.Contains(q, cfg.Auth.TokenURL) }) {
		problem("auth.token_url", "documented token endpoint required")
	}
	if !proven("items_path", cfg.ItemsPath, func(q string) bool {
		v, ok := jsonExample(q)
		if !ok {
			return false
		}
		items, err := mapping.Items(v, cfg.ItemsPath)
		return err == nil && len(items) > 0
	}) {
		problem("items_path", "cite a JSON response example containing the configured record array")
	}
	if !proven("pagination", cfg.Pagination.Type, func(q string) bool {
		q = strings.ToLower(q)
		if cfg.Pagination.Type == "none" {
			return strings.Contains(q, "no pagination") || strings.Contains(q, "single response")
		}
		if !strings.Contains(q, strings.ToLower(cfg.Pagination.Type)) {
			return false
		}
		for _, param := range []string{cfg.Pagination.PageParam, cfg.Pagination.OffsetParam, cfg.Pagination.SizeParam, cfg.Pagination.CursorParam, cfg.Pagination.CursorPath} {
			if param != "" && !strings.Contains(q, strings.ToLower(param)) {
				return false
			}
		}
		return true
	}) {
		problem("pagination", "documented pagination strategy and configured parameters required")
	}
	for dest, path := range mappedPaths(cfg, problem) {
		if !proven("field", path, func(q string) bool {
			v, ok := jsonExample(q)
			if !ok {
				return false
			}
			if items, e := mapping.Items(v, cfg.ItemsPath); e == nil && len(items) > 0 {
				return examplePath(items[0], path)
			}
			return examplePath(v, path)
		}) {
			problem("destination.mapping."+dest, "response path "+path+" is missing from cited JSON examples; do not invent it")
		}
	}
	if len(issues) == 0 {
		out.Evidence = checked
	}
	return issues
}

// mappedPaths enforces the no-invented-values rules every grounded draft
// shares and returns destination -> mapped response path for proof.
func mappedPaths(cfg config.Config, problem func(field, msg string)) map[string]string {
	paths := map[string]string{}
	for dest, field := range cfg.Destination.Mapping {
		if field.Default != nil && !(dest == "severity_id" && fmt.Sprint(field.Default) == "0") {
			problem("destination.mapping."+dest, "do not invent fallback record values; leave missing optional fields empty and quarantine missing required fields")
		}
		if field.Path == nil {
			if !strings.HasPrefix(dest, "metadata.product.") && !(dest == "severity_id" && fmt.Sprint(field.Constant) == "0") {
				problem("destination.mapping."+dest, "AI must map vendor facts from documented response fields rather than invent constant record values")
			}
			continue
		}
		paths[dest] = *field.Path
	}
	return paths
}

var inputPlaceholder = regexp.MustCompile(`your-[a-zA-Z0-9_-]+`)

// citedDocuments: the fetched references and the evidence that quotes them.
func citedDocuments(r Request, out *modelOutput) ([]string, []Evidence) {
	sources, cited := []string{}, []Evidence(nil)
	for source := range r.documents {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	for _, e := range out.Evidence {
		if doc, ok := r.documents[e.URL]; ok && strings.Contains(doc, compact(e.Quote)) {
			cited = append(cited, e)
		}
	}
	return sources, cited
}

const documentedAccess = "Evidence checked against the public references you supplied. Review the publisher, permissions and preview result before activation."

func documentedMetadata(d *Draft, r Request, cfg config.Config, sources []string, evidence []Evidence, profile, access string) {
	d.Sources, d.Evidence = sources, evidence
	d.AlsoAvailable = nil
	d.Optional = []string{"Review collection limits and schedule locally; every draft starts disabled."}
	d.Notes = []string{"The requested dataset and scope were retained. Execution settings have cited public-reference evidence; this is not a guarantee of publisher authenticity, subscription eligibility or working credentials.", "No customer notes, stored-secret metadata or collected records were supplied to the hosted model. Preview before activation.", "Scheduling, incremental checkpoints and notifications are configured separately after the API contract is tested."}
	d.Needed = []string{}
	if d.Credential != nil {
		d.Needed = append(d.Needed, "Supply these credential fields locally: "+strings.Join(d.Credential.Fields, ", ")+". Follow the cited authentication documentation; no additional permissions are inferred.")
	}
	fields := []string{}
	for _, f := range cfg.Destination.Mapping {
		if f.Path != nil {
			fields = append(fields, *f.Path)
		}
	}
	sort.Strings(fields)
	d.Contract = &Contract{Profile: profile, Scope: r.Dataset + " (" + r.Scope + ")", Access: access, Method: cfg.Request.Method, Endpoint: cfg.Request.URL, Auth: cfg.Auth.Type, ItemsPath: cfg.ItemsPath, Pagination: cfg.Pagination.Type, Fields: fields, Status: "documented_candidate"}
	seen := map[string]bool{}
	for _, x := range inputPlaceholder.FindAllString(cfg.Request.URL, -1) {
		if x == "your-tenant" {
			continue
		}
		if !seen[x] {
			seen[x] = true
			d.Inputs = append(d.Inputs, DraftInput{Name: x, Label: strings.ReplaceAll(strings.TrimPrefix(x, "your-"), "-", " "), Placeholder: x, Location: "path"})
			d.Needed = append(d.Needed, "Fill "+x+" locally before testing.")
		}
	}
}
