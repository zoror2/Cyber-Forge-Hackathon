package engine

// This file defines WHAT a connector config looks like (the request half of
// it) and how it is validated. Member B owns the full config (mapping,
// schedule, approval status) and embeds this Connector inside it.

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// idPattern restricts tenant and connector IDs to a safe alphabet:
// starts with a lowercase letter or digit, then letters/digits/-/_, max 64.
// Because "/" is not allowed, "tenant/connector" can be used as a cache key
// without two different pairs ever producing the same key.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Connector is the request side of one connection to a vendor API.
// JSON tags (`json:"..."`) are the field names used in the stored JSON config.
type Connector struct {
	// TenantID is set by the platform from the authenticated session or the
	// stored config row. Never copy it from user-supplied request data.
	TenantID   string     `json:"tenant_id"`
	ID         string     `json:"id"`         // unique per tenant, e.g. "crowdstrike_alerts"
	Request    Request    `json:"request"`    // which URL to call
	Auth       Auth       `json:"auth"`       // how to log in
	Pagination Pagination `json:"pagination"` // how to get the next page
	ItemsPath  string     `json:"items_path"` // where the record list sits in the JSON, "" = the whole response is the list
	Limits     Limits     `json:"limits"`     // safety caps
	Retry      Retry      `json:"retry"`      // retry behaviour
}

// Request describes the HTTP call (FR-2).
type Request struct {
	Method         string            `json:"method"`          // only GET for now (read-only platform)
	URL            string            `json:"url"`             // full https URL of the endpoint
	Params         map[string]string `json:"params"`          // query params, NON-secret only (e.g. limit=100)
	Headers        map[string]string `json:"headers"`         // extra headers, NON-secret only (e.g. Accept)
	TimeoutSeconds int               `json:"timeout_seconds"` // max time per request
	// AllowedPorts lists the ports this connector may connect to (API, next
	// pages and OAuth token URL). Default [443]. Anything else must be listed
	// explicitly so the approver sees it.
	AllowedPorts []int `json:"allowed_ports"`
}

// Auth says how to log in (FR-1). It holds the secret's NAME, never its value;
// the value is fetched from the SecretStore at run time.
type Auth struct {
	Type     string   `json:"type"`      // none | static | api_key | bearer | basic | oauth2_client_credentials
	Secret   string   `json:"secret"`    // secret NAME in the secret store, e.g. "crowdstrike"
	Header   string   `json:"header"`    // api_key only: header name, e.g. "X-API-Key"
	Username string   `json:"username"`  // basic only: e.g. the Jira account email
	TokenURL string   `json:"token_url"` // oauth2 only: where to get access tokens
	ClientID string   `json:"client_id"` // oauth2 only: the API client's ID (not secret); "" = take it from secret field "client_id"
	Scopes   []string `json:"scopes"`    // oauth2 only: optional permission scopes

	// static only: headers built from secret fields, e.g. Cortex XSIAM:
	//   {"name": "x-xdr-auth-id", "value": "{{secret.key_id}}"}
	//   {"name": "Authorization", "value": "{{secret.key}}"}
	// The only placeholder allowed is {{secret.<field>}}.
	Headers []HeaderTemplate `json:"headers"`

	// oauth2 only: extra NON-secret form fields for the token request,
	// e.g. Wiz needs {"audience": "wiz-api"}.
	ExtraParams map[string]string `json:"extra_params"`
}

// HeaderTemplate is one header of a static auth block.
type HeaderTemplate struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Pagination says how to walk through all pages of results (FR-3).
type Pagination struct {
	Type        string `json:"type"`                 // none | page | offset | link | cursor
	PageParam   string `json:"page_param"`           // page:   name of the page-number param, e.g. "page"
	StartPage   *int   `json:"start_page,omitempty"` // page: first page number (default 1; 0 for zero-based APIs)
	OffsetParam string `json:"offset_param"`         // offset: name of the offset param, e.g. "startAt"
	SizeParam   string `json:"size_param"`           // page/offset/cursor: name of the page-size param, e.g. "limit"
	PageSize    int    `json:"page_size"`            // records per page we ask for
	CursorParam string `json:"cursor_param"`         // cursor: param to send the cursor in, e.g. "after"
	CursorPath  string `json:"cursor_path"`          // cursor: where the next cursor is in the JSON, e.g. "meta.next"
	// link: no fields needed; the next URL comes from the HTTP "Link" header.
}

// Limits are safety caps so a broken or malicious vendor can't exhaust us.
type Limits struct {
	MaxResponseBytes int64 `json:"max_response_bytes"` // biggest single response we accept
	MaxPages         int   `json:"max_pages"`          // stop after this many pages
	MaxRunSeconds    int   `json:"max_run_seconds"`    // whole run must finish within this
}

// Retry controls behaviour on temporary failures (FR-7, FR-8).
type Retry struct {
	MaxAttempts          int `json:"max_attempts"`            // total tries; 4 = first try + retries after 1s, 2s, 4s
	BaseDelayMillis      int `json:"base_delay_ms"`           // first backoff delay; doubles each retry
	MaxRetryAfterSeconds int `json:"max_retry_after_seconds"` // if a 429 asks us to wait longer, give up this run
}

// withDefaults fills any field the config left empty with a safe default.
// It works on a copy (value receiver), so the caller's Connector is unchanged.
func (c Connector) withDefaults() Connector {
	setDefault(&c.Request.Method, "GET")
	setDefault(&c.Request.TimeoutSeconds, 30)
	if len(c.Request.AllowedPorts) == 0 {
		c.Request.AllowedPorts = []int{443} // standard HTTPS only
	}
	setDefault(&c.Auth.Type, "none")
	setDefault(&c.Pagination.Type, "none")
	if c.Pagination.Type == "page" && c.Pagination.StartPage == nil {
		one := 1
		c.Pagination.StartPage = &one
	}
	setDefault(&c.Limits.MaxResponseBytes, 10<<20) // 10 MB
	setDefault(&c.Limits.MaxPages, 1000)
	setDefault(&c.Limits.MaxRunSeconds, 900) // 15 minutes
	setDefault(&c.Retry.MaxAttempts, 4)      // waits 1s, 2s, 4s between tries
	setDefault(&c.Retry.BaseDelayMillis, 1000)
	setDefault(&c.Retry.MaxRetryAfterSeconds, 120)
	return c
}

// setDefault sets *field to value only if *field is still its zero value
// ("" for strings, 0 for numbers). Generic so it works for any type.
func setDefault[T comparable](field *T, value T) {
	var zero T
	if *field == zero {
		*field = value
	}
}

// sensitiveWords are words that suggest a credential. Secrets may only enter
// through the auth block, so a header or query param whose name contains one
// of these WORDS is rejected at validation time.
var sensitiveWords = map[string]bool{
	"auth": true, "authorization": true, "token": true, "key": true, "apikey": true,
	"secret": true, "password": true, "passwd": true, "pwd": true, "cookie": true,
	"session": true, "sessionid": true, "signature": true, "sig": true, "jwt": true,
	"bearer": true, "credential": true, "credentials": true, "pass": true,
}

// looksSensitive reports whether a header/param name looks like a credential.
// It matches whole words, so "apiKey" (api + key) is caught but NVD's
// legitimate "keywordSearch" (keyword + search) is allowed.
func looksSensitive(name string) bool {
	for _, w := range splitWords(name) {
		if sensitiveWords[w] {
			return true
		}
	}
	return false
}

// splitWords breaks a name into lowercase words:
//
//	"X-API-Key"   -> x, api, key
//	"api_key"     -> api, key
//	"apiKey"      -> api, key
//	"APIKey"      -> api, key
//	"accessToken" -> access, token
func splitWords(s string) []string {
	var words []string
	var cur []rune
	flush := func() { // end the current word and start a new one
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	runes := []rune(s)
	for i, r := range runes {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			// separators like "-", "_", "." end a word
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(runes[i-1]) ||
			(i+1 < len(runes) && unicode.IsLower(runes[i+1]) && unicode.IsUpper(runes[i-1]))):
			// camelCase boundary: "apiKey" splits before K;
			// acronym boundary: "APIKey" splits before K (next letter is lowercase)
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return words
}

// Validate checks the connector and returns EVERY problem at once (joined),
// so the UI/API can show all errors together instead of one at a time.
// URLs must be https. This is what the API and UI must call.
func (c Connector) Validate() error { return c.validate(false) }

// validate is Validate with one dev-only switch: allowHTTP also accepts
// http:// URLs. The engine passes egress.Policy.AllowHTTP here, which is
// refused in production by Policy.ProductionSafe, so plain HTTP can only ever
// work against the local mock vendor.
func (c Connector) validate(allowHTTP bool) error {
	c = c.withDefaults()
	okScheme := func(s string) bool { return s == "https" || (allowHTTP && s == "http") }
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	// --- identity ---
	if !idPattern.MatchString(c.TenantID) {
		bad("tenant_id is required (lowercase letters, digits, - or _, max 64)")
	}
	if !idPattern.MatchString(c.ID) {
		bad("id is required (lowercase letters, digits, - or _, max 64)")
	}

	// --- request ---
	if c.Request.Method != "GET" {
		bad("request.method must be GET (platform is read-only)")
	}
	if u, err := url.Parse(c.Request.URL); err != nil || !okScheme(u.Scheme) || u.Host == "" || u.User != nil {
		bad("request.url must be an absolute https URL without credentials")
	}
	if c.Request.TimeoutSeconds < 1 || c.Request.TimeoutSeconds > 120 {
		bad("request.timeout_seconds must be 1-120")
	}
	if len(c.Request.AllowedPorts) > 5 {
		bad("request.allowed_ports may list at most 5 ports")
	}
	for _, p := range c.Request.AllowedPorts {
		if p < 1 || p > 65535 {
			bad("request.allowed_ports: %d is not a valid port", p)
		}
	}
	// Secrets must never be typed into headers or params. "Host" is also
	// blocked because overriding it could confuse routing / host binding.
	for name := range c.Request.Headers {
		if looksSensitive(name) || strings.EqualFold(name, "host") {
			bad("request.headers.%s: credentials must go in the auth block, not headers", name)
		}
	}
	for name := range c.Request.Params {
		if looksSensitive(name) {
			bad("request.params.%s: credentials must go in the auth block, not query params", name)
		}
	}

	// --- auth: required fields per type ---
	a := c.Auth
	switch a.Type {
	case "none":
	case "static":
		validateStaticHeaders(a.Headers, bad)
	case "api_key":
		if a.Header == "" {
			bad("auth.header is required for api_key")
		}
	case "bearer":
	case "basic":
		if a.Username == "" {
			bad("auth.username is required for basic")
		}
	case "oauth2_client_credentials":
		if u, err := url.Parse(a.TokenURL); err != nil || !okScheme(u.Scheme) || u.Host == "" {
			bad("auth.token_url must be an absolute https URL")
		}
		for name := range a.ExtraParams {
			if looksSensitive(name) || reservedOAuthParam[name] {
				bad("auth.extra_params.%s is not allowed (secrets and grant fields are set by the engine)", name)
			}
		}
	default:
		bad("auth.type %q is not supported", a.Type)
	}
	if a.Type != "none" && a.Secret == "" {
		bad("auth.secret (the secret name) is required for %s", a.Type)
	}

	// --- pagination: required fields per style ---
	p := c.Pagination
	switch p.Type {
	case "none", "link":
	case "page":
		if p.PageParam == "" || p.PageSize < 1 {
			bad("pagination.page_param and page_size are required for page")
		}
	case "offset":
		if p.OffsetParam == "" || p.PageSize < 1 {
			bad("pagination.offset_param and page_size are required for offset")
		}
	case "cursor":
		if p.CursorParam == "" || p.CursorPath == "" {
			bad("pagination.cursor_param and cursor_path are required for cursor")
		}
	default:
		bad("pagination.type %q is not supported", p.Type)
	}
	// page/offset stop when a page is shorter than page_size, so the vendor
	// must actually be told the size we expect.
	if p.PageSize > 0 && p.SizeParam == "" && (p.Type == "page" || p.Type == "offset") {
		bad("pagination.size_param is required when page_size is set")
	}

	// --- limits and retry: keep values inside sane ranges ---
	// decoding JSON costs ~15x the body in memory (load test: 60 MB -> 926 MiB)
	if c.Limits.MaxResponseBytes < 1 || c.Limits.MaxResponseBytes > 25<<20 {
		bad("limits.max_response_bytes must be 1 byte to 25 MB")
	}
	if c.Limits.MaxPages < 1 || c.Limits.MaxPages > 100000 {
		bad("limits.max_pages must be 1-100000")
	}
	if c.Limits.MaxRunSeconds < 1 || c.Limits.MaxRunSeconds > 3600 {
		bad("limits.max_run_seconds must be 1-3600")
	}
	if c.Retry.MaxAttempts < 1 || c.Retry.MaxAttempts > 10 {
		bad("retry.max_attempts must be 1-10")
	}
	if c.Retry.BaseDelayMillis < 1 || c.Retry.BaseDelayMillis > 60000 {
		bad("retry.base_delay_ms must be 1-60000")
	}
	if c.Retry.MaxRetryAfterSeconds < 1 || c.Retry.MaxRetryAfterSeconds > 900 {
		bad("retry.max_retry_after_seconds must be 1-900")
	}

	// Placeholders are only allowed inside auth.headers. Anywhere else they
	// would be sent literally, which means a template wasn't resolved.
	for name, v := range c.Request.Headers {
		if strings.Contains(v, "{{") {
			bad("request.headers.%s: placeholders are not allowed here", name)
		}
	}
	for name, v := range c.Request.Params {
		if strings.Contains(v, "{{") {
			bad("request.params.%s: placeholders are not allowed here", name)
		}
	}

	return errors.Join(errs...) // nil if errs is empty
}

// reservedOAuthParam are token-request fields the engine sets itself.
var reservedOAuthParam = map[string]bool{"grant_type": true, "scope": true, "client_id": true, "client_secret": true}

// headerName is an RFC 9110 header field name ("token" characters).
var headerName = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")

// validateStaticHeaders checks a static auth block: 1-5 well-formed, unique
// header names, values that use ONLY {{secret.<field>}} placeholders, and at
// least one placeholder overall (otherwise there's no credential at all).
func validateStaticHeaders(hs []HeaderTemplate, bad func(string, ...any)) {
	if len(hs) == 0 || len(hs) > 5 {
		bad("auth.headers must list 1-5 headers for static")
		return
	}
	seen := map[string]bool{}
	placeholders := 0
	for i, h := range hs {
		if !headerName.MatchString(h.Name) || strings.EqualFold(h.Name, "host") {
			bad("auth.headers[%d].name %q is not a valid header name", i, h.Name)
		}
		if seen[strings.ToLower(h.Name)] {
			bad("auth.headers[%d].name %q is listed twice", i, h.Name)
		}
		seen[strings.ToLower(h.Name)] = true
		fields, err := secretPlaceholders(h.Value)
		if err != nil {
			bad("auth.headers[%d].value: %v", i, err)
		}
		placeholders += len(fields)
	}
	if placeholders == 0 {
		bad("auth.headers must use at least one {{secret.<field>}} placeholder")
	}
}
