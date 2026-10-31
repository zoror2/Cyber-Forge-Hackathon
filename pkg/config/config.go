// Package config defines the shared, declarative contract used by both teammates.
package config

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const MaxBytes = 256 << 10

var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func ValidID(s string) bool { return identifier.MatchString(s) }

type Config struct {
	Version     int         `json:"version" yaml:"version"`
	ID          string      `json:"id" yaml:"id"`
	Name        string      `json:"name" yaml:"name"`
	Request     Request     `json:"request" yaml:"request"`
	Auth        Auth        `json:"auth" yaml:"auth"`
	Response    Response    `json:"response" yaml:"response"`
	Pagination  Pagination  `json:"pagination" yaml:"pagination"`
	Schedule    Schedule    `json:"schedule" yaml:"schedule"`
	Destination Destination `json:"destination" yaml:"destination"`
	Limits      Limits      `json:"limits" yaml:"limits"`
	Retry       Retry       `json:"retry" yaml:"retry"`
}
type Request struct {
	Method         string            `json:"method" yaml:"method"`
	URL            string            `json:"url" yaml:"url"`
	Params         map[string]string `json:"params" yaml:"params"`
	Headers        map[string]string `json:"headers" yaml:"headers"`
	TimeoutSeconds int               `json:"timeout_seconds" yaml:"timeout_seconds"`
}
type Auth struct {
	Type       string `json:"type" yaml:"type"`
	SecretName string `json:"secret_name,omitempty" yaml:"secret_name,omitempty"`
	Header     string `json:"header,omitempty" yaml:"header,omitempty"`
	TokenURL   string `json:"token_url,omitempty" yaml:"token_url,omitempty"`
	Scope      string `json:"scope,omitempty" yaml:"scope,omitempty"`
}
type Response struct {
	ItemsPath string `json:"items_path" yaml:"items_path"`
}
type Pagination struct {
	Type        string `json:"type" yaml:"type"`
	PageParam   string `json:"page_param,omitempty" yaml:"page_param,omitempty"`
	OffsetParam string `json:"offset_param,omitempty" yaml:"offset_param,omitempty"`
	LimitParam  string `json:"limit_param,omitempty" yaml:"limit_param,omitempty"`
	CursorParam string `json:"cursor_param,omitempty" yaml:"cursor_param,omitempty"`
	CursorPath  string `json:"cursor_path,omitempty" yaml:"cursor_path,omitempty"`
	TotalPath   string `json:"total_path,omitempty" yaml:"total_path,omitempty"`
	Header      string `json:"header,omitempty" yaml:"header,omitempty"`
	Relation    string `json:"relation,omitempty" yaml:"relation,omitempty"`
	Start       int    `json:"start" yaml:"start"`
	PageSize    int    `json:"page_size" yaml:"page_size"`
}
type Schedule struct {
	Enabled         bool `json:"enabled" yaml:"enabled"`
	IntervalSeconds int  `json:"interval_seconds" yaml:"interval_seconds"`
}
type Destination struct {
	Entity  string           `json:"entity" yaml:"entity"`
	Mapping map[string]Field `json:"mapping" yaml:"mapping"`
}
type Field struct {
	Path      *string           `json:"path,omitempty" yaml:"path,omitempty"`
	Constant  any               `json:"constant,omitempty" yaml:"constant,omitempty"`
	Required  bool              `json:"required" yaml:"required"`
	Default   any               `json:"default,omitempty" yaml:"default,omitempty"`
	Transform string            `json:"transform,omitempty" yaml:"transform,omitempty"`
	Format    string            `json:"format,omitempty" yaml:"format,omitempty"`
	Timezone  string            `json:"timezone,omitempty" yaml:"timezone,omitempty"`
	Precision string            `json:"precision,omitempty" yaml:"precision,omitempty"`
	Lookup    map[string]string `json:"lookup,omitempty" yaml:"lookup,omitempty"`
}
type Limits struct {
	MaxPages         int   `json:"max_pages" yaml:"max_pages"`
	MaxRecords       int   `json:"max_records" yaml:"max_records"`
	MaxResponseBytes int64 `json:"max_response_bytes" yaml:"max_response_bytes"`
	MaxRunSeconds    int   `json:"max_run_seconds" yaml:"max_run_seconds"`
}
type Retry struct {
	MaxAttempts       int `json:"max_attempts" yaml:"max_attempts"`
	BaseDelaySeconds  int `json:"base_delay_seconds" yaml:"base_delay_seconds"`
	MaxBackoffSeconds int `json:"max_backoff_seconds" yaml:"max_backoff_seconds"`
}
type Issue struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Decode accepts one JSON or YAML document. Parser errors intentionally omit input values.
func Decode(body []byte) (Config, []Issue) {
	var c Config
	if len(body) > MaxBytes {
		return c, []Issue{{"config", "exceeds 256 KiB"}}
	}
	var node yaml.Node
	if err := yaml.Unmarshal(body, &node); err != nil {
		return c, []Issue{{"config", "invalid YAML/JSON"}}
	}
	var safe func(*yaml.Node, int) bool
	safe = func(n *yaml.Node, depth int) bool {
		if depth > 30 || n.Kind == yaml.AliasNode || n.Anchor != "" || (n.Tag != "" && !strings.HasPrefix(n.Tag, "!!")) {
			return false
		}
		for _, child := range n.Content {
			if !safe(child, depth+1) {
				return false
			}
		}
		return true
	}
	if !safe(&node, 0) {
		return c, []Issue{{"config", "aliases, anchors or excessive nesting are not supported"}}
	}
	d := yaml.NewDecoder(bytes.NewReader(body))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return c, []Issue{{"config", "unknown/duplicate key or wrong field type"}}
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return c, []Issue{{"config", "exactly one document is required"}}
	}
	c.Defaults()
	return c, c.Validate()
}
func (c *Config) Defaults() {
	if c.Auth.Type == "" {
		c.Auth.Type = "none"
	}
	if c.Pagination.Type == "" {
		c.Pagination.Type = "none"
	}
	if c.Request.TimeoutSeconds == 0 {
		c.Request.TimeoutSeconds = 20
	}
	if c.Limits.MaxPages == 0 {
		c.Limits.MaxPages = 100
	}
	if c.Limits.MaxRecords == 0 {
		c.Limits.MaxRecords = 10000
	}
	if c.Limits.MaxResponseBytes == 0 {
		c.Limits.MaxResponseBytes = 10 << 20
	}
	if c.Limits.MaxRunSeconds == 0 {
		c.Limits.MaxRunSeconds = 300
	}
	if c.Retry.MaxAttempts == 0 {
		c.Retry.MaxAttempts = 4
	}
	if c.Retry.BaseDelaySeconds == 0 {
		c.Retry.BaseDelaySeconds = 1
	}
	if c.Retry.MaxBackoffSeconds == 0 {
		c.Retry.MaxBackoffSeconds = 30
	}
}
func SafeURL(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	return ValidHost(u.Hostname())
}
func ValidHost(host string) bool {
	if host == "" || host != strings.ToLower(host) || strings.ContainsAny(host, "/:@?# \\\t\r\n") || strings.HasSuffix(host, ".") {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	}
	if !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func sensitive(s string) bool {
	s = strings.ToLower(s)
	for _, word := range []string{"token", "secret", "password", "credential", "authorization", "cookie", "apikey", "api_key", "api-key"} {
		if strings.Contains(s, word) {
			return true
		}
	}
	return s == "key"
}

var Fields = map[string][]string{
	"user":   {"id", "name", "email", "status", "last_login"},
	"device": {"id", "hostname", "ip", "os", "owner", "last_seen"},
	"event":  {"id", "type", "severity", "timestamp", "description"},
}

func (c Config) Validate() []Issue {
	issues := []Issue{}
	add := func(k, m string) { issues = append(issues, Issue{k, m}) }
	if c.Version != 1 {
		add("version", "must be 1")
	}
	if !ValidID(c.ID) {
		add("id", "use 1-64 letters, digits, underscores or hyphens")
	}
	if strings.TrimSpace(c.Name) == "" || len(c.Name) > 200 {
		add("name", "must contain 1-200 characters")
	}
	if c.Request.Method != "GET" {
		add("request.method", "only GET is supported")
	}
	if !SafeURL(c.Request.URL) {
		add("request.url", "requires a public HTTPS host on port 443, no credentials, query or fragment; use params for query values")
	}
	if c.Request.TimeoutSeconds < 1 || c.Request.TimeoutSeconds > 120 {
		add("request.timeout_seconds", "must be 1-120")
	}
	for k, v := range c.Request.Headers {
		if !strings.EqualFold(k, "Accept") && !strings.EqualFold(k, "User-Agent") {
			add("request.headers", "only Accept and User-Agent are allowed; configure credentials through auth")
		}
		if strings.ContainsAny(v, "\r\n") {
			add("request.headers", "control characters are forbidden")
		}
	}
	for k := range c.Request.Params {
		if sensitive(k) {
			add("request.params", "credential-like parameter names are forbidden")
		}
	}
	switch c.Auth.Type {
	case "none":
		if c.Auth.SecretName != "" {
			add("auth.secret_name", "must be empty for none")
		}
	case "api_key", "basic", "bearer", "oauth2_client_credentials":
		if !ValidID(c.Auth.SecretName) {
			add("auth.secret_name", "a valid stored secret name is required")
		}
	default:
		add("auth.type", "unsupported authentication type")
	}
	if c.Auth.Type == "api_key" && (c.Auth.Header == "" || !regexp.MustCompile(`^[A-Za-z0-9-]+$`).MatchString(c.Auth.Header) || strings.EqualFold(c.Auth.Header, "Host") || strings.EqualFold(c.Auth.Header, "Cookie")) {
		add("auth.header", "a safe API-key header name is required")
	}
	if c.Auth.Type == "oauth2_client_credentials" && !SafeURL(c.Auth.TokenURL) {
		add("auth.token_url", "a public HTTPS token endpoint is required")
	}
	p := c.Pagination
	switch p.Type {
	case "none":
	case "next_link":
		if p.Header == "" || p.Relation == "" {
			add("pagination", "header and relation are required")
		}
	case "offset":
		if p.OffsetParam == "" || p.LimitParam == "" || p.PageSize < 1 {
			add("pagination", "offset_param, limit_param and positive page_size are required")
		}
	case "page_number":
		if p.PageParam == "" || p.LimitParam == "" || p.PageSize < 1 {
			add("pagination", "page_param, limit_param and positive page_size are required")
		}
	case "cursor":
		if p.CursorParam == "" || p.CursorPath == "" {
			add("pagination", "cursor_param and cursor_path are required")
		}
	default:
		add("pagination.type", "unsupported pagination type")
	}
	if p.Start < 0 || p.PageSize > 10000 {
		add("pagination", "start must be nonnegative and page_size at most 10000")
	}
	for _, k := range []string{p.OffsetParam, p.LimitParam, p.PageParam, p.CursorParam} {
		if sensitive(k) {
			add("pagination", "credential-like parameter names are forbidden")
		}
	}
	if c.Schedule.Enabled && (c.Schedule.IntervalSeconds < 1 || c.Schedule.IntervalSeconds > 86400*365) {
		add("schedule.interval_seconds", "must be 1-31536000 when enabled")
	}
	if c.Limits.MaxPages < 1 || c.Limits.MaxPages > 1000 || c.Limits.MaxRecords < 1 || c.Limits.MaxRecords > 1000000 || c.Limits.MaxResponseBytes < 1 || c.Limits.MaxResponseBytes > 100<<20 || c.Limits.MaxRunSeconds < 1 || c.Limits.MaxRunSeconds > 3600 {
		add("limits", "pages 1-1000, records 1-1000000, bytes 1-104857600, seconds 1-3600 required")
	}
	if c.Retry.MaxAttempts < 1 || c.Retry.MaxAttempts > 10 || c.Retry.BaseDelaySeconds < 1 || c.Retry.MaxBackoffSeconds < 1 || c.Retry.MaxBackoffSeconds > 300 {
		add("retry", "attempts 1-10 and positive delays (backoff <=300) required")
	}
	fields, ok := Fields[c.Destination.Entity]
	if !ok {
		add("destination.entity", "must be user, device or event")
	}
	allowed := map[string]bool{}
	for _, f := range fields {
		allowed[f] = true
	}
	for name, spec := range c.Destination.Mapping {
		key := "destination.mapping." + name
		if !allowed[name] {
			add(key, "unknown field or engine-owned provenance")
		}
		if (spec.Path != nil) == (spec.Constant != nil) {
			add(key, "provide exactly one path or non-null constant")
		}
		switch spec.Transform {
		case "", "string", "integer", "datetime", "lookup":
		default:
			add(key+".transform", "unsupported transform")
		}
		if spec.Transform == "lookup" && len(spec.Lookup) == 0 {
			add(key+".lookup", "lookup table required")
		}
		if spec.Timezone != "" {
			if _, err := time.LoadLocation(spec.Timezone); err != nil {
				add(key+".timezone", "unknown timezone")
			}
		}
		if spec.Precision != "" && (spec.Precision != "date" || name != "timestamp" || spec.Transform != "datetime") {
			add(key+".precision", "date precision is supported only for transformed event timestamps")
		}
		if strings.Contains(spec.Format, "%") {
			add(key+".format", "use Go layouts such as 2006-01-02, not strftime")
		}
	}
	required := []string{"id"}
	if c.Destination.Entity == "event" {
		required = append(required, "type", "description", "timestamp")
	}
	for _, f := range required {
		if _, ok := c.Destination.Mapping[f]; !ok {
			add("destination.mapping."+f, "required mapping is missing")
		}
	}
	return issues
}
func (i Issue) Error() string { return fmt.Sprintf("%s: %s", i.Field, i.Message) }
