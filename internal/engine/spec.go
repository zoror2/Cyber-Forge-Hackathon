package engine

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Connector is the request side of a connection config. Member B owns the full
// config (mapping, schedule, destination) and embeds or converts to this.
type Connector struct {
	ID         string     `json:"id"`
	Request    Request    `json:"request"`
	Auth       Auth       `json:"auth"`
	Pagination Pagination `json:"pagination"`
	ItemsPath  string     `json:"items_path"` // dotted path to the array of records; "" = root
	Limits     Limits     `json:"limits"`
	Retry      Retry      `json:"retry"`
}

type Request struct {
	Method         string            `json:"method"` // GET only (read-only platform)
	URL            string            `json:"url"`
	Params         map[string]string `json:"params"`  // non-secret only
	Headers        map[string]string `json:"headers"` // non-secret only
	TimeoutSeconds int               `json:"timeout_seconds"`
}

// Auth names a secret; it never contains a secret value.
type Auth struct {
	Type     string   `json:"type"`      // none | api_key | bearer | basic | oauth2_client_credentials
	Secret   string   `json:"secret"`    // secret NAME in the secret store
	Header   string   `json:"header"`    // api_key: header name, e.g. X-API-Key
	Username string   `json:"username"`  // basic: e.g. Jira account email
	TokenURL string   `json:"token_url"` // oauth2
	ClientID string   `json:"client_id"` // oauth2
	Scopes   []string `json:"scopes"`    // oauth2
}

type Pagination struct {
	Type        string `json:"type"` // none | page | offset | link | cursor
	PageParam   string `json:"page_param"`
	StartPage   int    `json:"start_page"`
	OffsetParam string `json:"offset_param"`
	SizeParam   string `json:"size_param"`
	PageSize    int    `json:"page_size"`
	CursorParam string `json:"cursor_param"`
	CursorPath  string `json:"cursor_path"` // dotted path to the next cursor in the body
}

type Limits struct {
	MaxResponseBytes int64 `json:"max_response_bytes"`
	MaxPages         int   `json:"max_pages"`
	MaxRunSeconds    int   `json:"max_run_seconds"`
}

type Retry struct {
	MaxAttempts          int `json:"max_attempts"` // total tries; 4 = first try + retries after 1s, 2s, 4s
	BaseDelayMillis      int `json:"base_delay_ms"`
	MaxRetryAfterSeconds int `json:"max_retry_after_seconds"` // longer Retry-After = give up this run
}

func (c Connector) withDefaults() Connector {
	setDefault(&c.Request.Method, "GET")
	setDefault(&c.Request.TimeoutSeconds, 30)
	setDefault(&c.Auth.Type, "none")
	setDefault(&c.Pagination.Type, "none")
	if c.Pagination.Type == "page" {
		setDefault(&c.Pagination.StartPage, 1)
	}
	setDefault(&c.Limits.MaxResponseBytes, 10<<20)
	setDefault(&c.Limits.MaxPages, 1000)
	setDefault(&c.Limits.MaxRunSeconds, 900)
	setDefault(&c.Retry.MaxAttempts, 4)
	setDefault(&c.Retry.BaseDelayMillis, 1000)
	setDefault(&c.Retry.MaxRetryAfterSeconds, 120)
	return c
}

func setDefault[T comparable](field *T, value T) {
	var zero T
	if *field == zero {
		*field = value
	}
}

// Names that suggest a credential. Secrets may only enter through the auth block,
// so a header or query parameter with one of these names is rejected outright.
var sensitiveWords = []string{"auth", "token", "key", "secret", "password", "passwd", "cookie", "session", "signature", "credential"}

func looksSensitive(name string) bool {
	n := strings.ToLower(name)
	for _, w := range sensitiveWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// Validate returns every problem at once so the UI/API can show them together.
func (c Connector) Validate() error {
	c = c.withDefaults()
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.ID == "" {
		bad("id is required")
	}
	if c.Request.Method != "GET" {
		bad("request.method must be GET (platform is read-only)")
	}
	if u, err := url.Parse(c.Request.URL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		bad("request.url must be an absolute https URL without credentials")
	}
	if c.Request.TimeoutSeconds < 1 || c.Request.TimeoutSeconds > 120 {
		bad("request.timeout_seconds must be 1-120")
	}
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

	a := c.Auth
	switch a.Type {
	case "none":
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
		if u, err := url.Parse(a.TokenURL); err != nil || u.Scheme != "https" || u.Host == "" {
			bad("auth.token_url must be an absolute https URL")
		}
		if a.ClientID == "" {
			bad("auth.client_id is required for oauth2_client_credentials")
		}
	default:
		bad("auth.type %q is not supported", a.Type)
	}
	if a.Type != "none" && a.Secret == "" {
		bad("auth.secret (the secret name) is required for %s", a.Type)
	}

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
	if p.PageSize > 0 && p.SizeParam == "" && (p.Type == "page" || p.Type == "offset") {
		bad("pagination.size_param is required when page_size is set")
	}

	if c.Limits.MaxResponseBytes < 1 || c.Limits.MaxResponseBytes > 100<<20 {
		bad("limits.max_response_bytes must be 1 byte to 100 MB")
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
	return errors.Join(errs...)
}
