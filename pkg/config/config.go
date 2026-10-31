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
	"sort"
	"strings"
	"time"

	"configbridge/internal/engine"
	"configbridge/pkg/ocsf"
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
	Filter      []Condition       `json:"filter"`
	Destination Destination       `json:"destination"`
}

// Condition keeps a vendor record only when it matches. All conditions must
// match (AND). Dropped records are counted as "skipped", never silently lost.
type Condition struct {
	Path  string `json:"path"`  // where to look in the vendor record, e.g. "knownRansomwareCampaignUse"
	Op    string `json:"op"`    // equals | not_equals | in | exists | within_days
	Value any    `json:"value"` // scalar; list for "in"; days for "within_days"; true/false for "exists"
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

// Destination is the OCSF class every record becomes, and how vendor fields
// map onto OCSF attribute paths (e.g. "vulnerabilities.0.cve.uid").
type Destination struct {
	Class      string           `json:"class"`       // OCSF class name, e.g. "vulnerability_finding"
	ActivityID int              `json:"activity_id"` // optional; default per class (Create / Collect)
	Mapping    map[string]Field `json:"mapping"`     // OCSF path -> where the value comes from
}
type Field struct {
	Path      *string           `json:"path,omitempty"`
	Constant  any               `json:"constant,omitempty"`
	Required  bool              `json:"required,omitempty"`
	Default   any               `json:"default,omitempty"`
	Transform string            `json:"transform,omitempty"`
	Format    string            `json:"format,omitempty"`
	Timezone  string            `json:"timezone,omitempty"`
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
	if c.Pagination.Type == "page" && c.Pagination.StartPage == nil {
		one := 1
		c.Pagination.StartPage = &one // explicit 0 stays 0 (zero-based APIs)
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

var filterPath = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}(\.[A-Za-z0-9_]{1,64}){0,7}$`)

// platformFilled are OCSF fields the platform sets when a config doesn't map them.
var platformFilled = map[string]bool{"time": true, "severity_id": true, "metadata": true, "metadata.product": true}

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
	out = append(out, c.validateFilter()...)
	out = append(out, c.validateDestination()...)
	return out
}
func (c Config) validateFilter() []Issue {
	out := []Issue{}
	if len(c.Filter) > 10 {
		out = append(out, Issue{"filter", "at most 10 conditions"})
	}
	for i, f := range c.Filter {
		key := fmt.Sprintf("filter.%d", i)
		if !filterPath.MatchString(f.Path) {
			out = append(out, Issue{key + ".path", "dotted field path required"})
		}
		switch f.Op {
		case "equals", "not_equals":
			if !scalar(f.Value) {
				out = append(out, Issue{key + ".value", "scalar value required"})
			}
		case "in":
			list, ok := f.Value.([]any)
			if !ok || len(list) == 0 || len(list) > 100 {
				out = append(out, Issue{key + ".value", "list of 1-100 scalars required"})
				continue
			}
			for _, v := range list {
				if !scalar(v) {
					out = append(out, Issue{key + ".value", "list of 1-100 scalars required"})
					break
				}
			}
		case "exists":
			if _, ok := f.Value.(bool); !ok && f.Value != nil {
				out = append(out, Issue{key + ".value", "true, false or omitted"})
			}
		case "within_days":
			n, e := json.Number(fmt.Sprint(f.Value)).Int64()
			if e != nil || n < 1 || n > 3650 {
				out = append(out, Issue{key + ".value", "whole number of days 1-3650"})
			}
		default:
			out = append(out, Issue{key + ".op", "must be equals, not_equals, in, exists or within_days"})
		}
	}
	return out
}

func scalar(v any) bool {
	switch v.(type) {
	case string, bool, json.Number, float64:
		return true
	}
	return false
}

func (c Config) validateDestination() []Issue {
	out := []Issue{}
	add := func(k, m string) { out = append(out, Issue{k, m}) }
	class, ok := ocsf.Lookup(c.Destination.Class)
	if !ok {
		add("destination.class", "must be one of "+strings.Join(ocsf.Classes(), ", "))
		return out
	}
	if c.Destination.ActivityID != 0 {
		if _, ok := class.Attributes["activity_id"].Enum[fmt.Sprint(c.Destination.ActivityID)]; !ok {
			add("destination.activity_id", "not an activity of this OCSF class")
		}
	}
	if len(c.Destination.Mapping) == 0 || len(c.Destination.Mapping) > 200 {
		add("destination.mapping", "1-200 mapped OCSF fields required")
	}
	normalized := map[string]bool{}
	for path, spec := range c.Destination.Mapping {
		key := "destination.mapping." + path
		if _, e := ocsf.Resolve(class, path); e != nil {
			add(key, "not a mappable OCSF "+class.Name+" field: "+e.Error())
			continue
		}
		normalized[normalize(path)] = true
		if (spec.Path != nil) == (spec.Constant != nil) {
			add(key, "provide exactly one path or non-null constant")
		}
		switch spec.Transform {
		case "", "string", "trim", "integer", "datetime", "lookup":
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
	}
	id := ocsf.Identity[class.Name]
	if spec, ok := c.Destination.Mapping[id]; !ok || !spec.Required {
		add("destination.mapping."+id, "the record identity must be mapped with required: true")
	}
	out = append(out, requiredCovered(class.Attributes, normalized, "")...)
	return out
}

// normalize turns array indexes into "#": "vulnerabilities.0.cve.uid" -> "vulnerabilities.#.cve.uid".
func normalize(path string) string {
	segs := strings.Split(path, ".")
	for i, s := range segs {
		if s != "" && strings.Trim(s, "0123456789") == "" {
			segs[i] = "#"
		}
	}
	return strings.Join(segs, ".")
}

// requiredCovered reports OCSF-required attributes the mapping never sets: on the
// class itself, and inside every object the mapping writes into.
func requiredCovered(attrs map[string]ocsf.Attr, mapped map[string]bool, prefix string) []Issue {
	out := []Issue{}
	names := make([]string, 0, len(attrs))
	for n := range attrs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		a := attrs[name]
		p := prefix + name
		if a.IsArray {
			p += ".#"
		}
		present := false
		for m := range mapped {
			if m == p || strings.HasPrefix(m, p+".") {
				present = true
				break
			}
		}
		bare := strings.TrimSuffix(p, ".#")
		if a.Requirement == "required" && !present && !ocsf.PlatformOwned[bare] && !platformFilled[bare] {
			out = append(out, Issue{"destination.mapping." + p, "required by OCSF; map it"})
		}
		if present && a.Type == "object_t" {
			if sub := ocsf.ObjectAttributes(a.ObjectType); len(sub) > 0 {
				out = append(out, requiredCovered(sub, mapped, p+".")...)
			}
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
