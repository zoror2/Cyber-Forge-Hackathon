// Package config adds mapping and scheduling to Member A's request contract.
// Tenant identity is supplied separately by authentication, never decoded here.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"configbridge/internal/engine"
)

const MaxBytes = 256 << 10

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func ValidID(s string) bool { return identifier.MatchString(s) }

type Config struct {
	Version     int               `json:"version"`
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Request     engine.Request    `json:"request"`
	Auth        engine.Auth       `json:"auth"`
	ItemsPath   string            `json:"items_path"`
	Pagination  engine.Pagination `json:"pagination"`
	Limits      Limits            `json:"limits"`
	Retry       engine.Retry      `json:"retry"`
	Schedule    Schedule          `json:"schedule"`
	Destination Destination       `json:"destination"`
}
type Limits struct {
	MaxResponseBytes int64 `json:"max_response_bytes"`
	MaxPages         int   `json:"max_pages"`
	MaxRunSeconds    int   `json:"max_run_seconds"`
	MaxRecords       int   `json:"max_records"`
}
type Schedule struct {
	Enabled         bool `json:"enabled"`
	IntervalSeconds int  `json:"interval_seconds"`
}
type Destination struct {
	Entity  string           `json:"entity"`
	Mapping map[string]Field `json:"mapping"`
}
type Field struct {
	Path      *string           `json:"path,omitempty"`
	Constant  any               `json:"constant,omitempty"`
	Required  bool              `json:"required,omitempty"`
	Default   any               `json:"default,omitempty"`
	Transform string            `json:"transform,omitempty"`
	Format    string            `json:"format,omitempty"`
	Timezone  string            `json:"timezone,omitempty"`
	Precision string            `json:"precision,omitempty"`
	Lookup    map[string]string `json:"lookup,omitempty"`
}
type Issue struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (i Issue) Error() string { return i.Field + ": " + i.Message }

// CheckJSON rejects duplicate keys at any level, excessive nesting and trailing
// documents. Secret request bodies use the same parser without echoing values.
func CheckJSON(body []byte) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 30 {
			return errors.New("nesting_limit")
		}
		token, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return errors.New("duplicate_key")
				}
				seen[s] = true
				if e = visit(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := visit(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("invalid_json")
		}
		_, e = d.Token()
		return e
	}
	if e := visit(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing_json")
	}
	return nil
}
func Decode(body []byte) (Config, []Issue) {
	var c Config
	if len(body) > MaxBytes {
		return c, []Issue{{"config", "exceeds 256 KiB"}}
	}
	if CheckJSON(body) != nil {
		return c, []Issue{{"config", "invalid JSON, duplicate key, trailing content or excessive nesting"}}
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	d.UseNumber()
	if d.Decode(&c) != nil {
		return c, []Issue{{"config", "unknown key (including tenant_id) or wrong field type"}}
	}
	c.Defaults()
	return c, c.Validate()
}
func (c Config) Connector(tenant string) engine.Connector {
	return engine.Connector{TenantID: tenant, ID: c.ID, Request: c.Request, Auth: c.Auth, ItemsPath: c.ItemsPath, Pagination: c.Pagination, Limits: engine.Limits{MaxResponseBytes: c.Limits.MaxResponseBytes, MaxPages: c.Limits.MaxPages, MaxRunSeconds: c.Limits.MaxRunSeconds}, Retry: c.Retry}
}
func (c *Config) Defaults() {
	if c.Request.Method == "" {
		c.Request.Method = "GET"
	}
	if c.Request.TimeoutSeconds == 0 {
		c.Request.TimeoutSeconds = 20
	}
	if c.Auth.Type == "" {
		c.Auth.Type = "none"
	}
	if c.Pagination.Type == "" {
		c.Pagination.Type = "none"
	}
	if c.Pagination.Type == "page" && c.Pagination.StartPage == 0 {
		c.Pagination.StartPage = 1
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
	if c.Retry.BaseDelayMillis == 0 {
		c.Retry.BaseDelayMillis = 1000
	}
	if c.Retry.MaxRetryAfterSeconds == 0 {
		c.Retry.MaxRetryAfterSeconds = 120
	}
}

var Fields = map[string][]string{"user": {"id", "name", "email", "status", "last_login"}, "device": {"id", "hostname", "ip", "os", "owner", "last_seen"}, "event": {"id", "type", "severity", "timestamp", "description"}}

func (c Config) Validate() []Issue {
	out := []Issue{}
	add := func(k, m string) { out = append(out, Issue{k, m}) }
	if err := c.Connector("validation").Validate(); err != nil {
		// Member A owns request semantics. Do not echo arbitrary config values.
		for _, line := range strings.Split(err.Error(), "\n") {
			field := strings.Fields(line)
			key := "request"
			if len(field) > 0 {
				candidate := strings.TrimSuffix(field[0], ":")
				if regexp.MustCompile(`^[a-z_]+(\.[a-z_]+)*$`).MatchString(candidate) {
					key = candidate
				}
			}
			add(key, "invalid request-side setting; check required fields and supported values")
		}
	}
	if c.Version != 1 {
		add("version", "must be 1")
	}
	if strings.TrimSpace(c.Name) == "" || len(c.Name) > 200 {
		add("name", "must contain 1-200 characters")
	}
	if c.Limits.MaxRecords < 1 || c.Limits.MaxRecords > 1000000 {
		add("limits.max_records", "must be 1-1000000")
	}
	if c.Schedule.Enabled && (c.Schedule.IntervalSeconds < 1 || c.Schedule.IntervalSeconds > 31536000) {
		add("schedule.interval_seconds", "must be 1-31536000 when enabled")
	}
	// URLs must carry noncredential query values through params, never inline.
	for _, raw := range []string{c.Request.URL, c.Auth.TokenURL} {
		if raw == "" {
			continue
		}
		u, e := url.Parse(raw)
		if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			add("request.url", "use a credential-free URL; put query values in params")
		}
	}
	allowed := map[string]bool{}
	names, ok := Fields[c.Destination.Entity]
	if !ok {
		add("destination.entity", "must be user, device or event")
	}
	for _, f := range names {
		allowed[f] = true
	}
	for name, spec := range c.Destination.Mapping {
		key := "destination.mapping." + name
		if !allowed[name] {
			add("destination.mapping", "unknown field or engine-owned provenance")
			continue
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
			if _, e := time.LoadLocation(spec.Timezone); e != nil {
				add(key+".timezone", "unknown timezone")
			}
		}
		if strings.Contains(spec.Format, "%") {
			add(key+".format", "use Go layouts such as 2006-01-02")
		}
		if spec.Precision != "" && (spec.Precision != "date" || name != "timestamp" || spec.Transform != "datetime") {
			add(key+".precision", "date precision is only valid for transformed event timestamps")
		}
	}
	required := []string{"id"}
	if c.Destination.Entity == "event" {
		required = append(required, "type", "timestamp", "description")
	}
	for _, f := range required {
		if _, ok := c.Destination.Mapping[f]; !ok {
			add("destination.mapping."+f, "required mapping is missing")
		}
	}
	return out
}
func ValidHost(host string) bool {
	if host == "" || host != strings.ToLower(host) || strings.ContainsAny(host, "/@?# \\\t\r\n") {
		return false
	}
	u, e := url.Parse("https://" + host)
	return e == nil && u.Host == host && u.Hostname() != "" && u.User == nil && u.Path == ""
}
func (c Config) String() string { return fmt.Sprintf("Config(%s)", c.ID) }
