package onboarding

import (
	"configbridge/internal/engine"
	"configbridge/pkg/config"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

type MappingRow struct {
	Name     string
	Date     bool
	Required bool
	Constant string
}

func MappingRows(entity string) []MappingRow {
	out := []MappingRow{}
	for _, name := range config.Fields[entity] {
		row := MappingRow{Name: name, Date: name == "timestamp" || name == "last_login" || name == "last_seen", Required: name == "id" || (entity == "event" && (name == "type" || name == "description" || name == "timestamp"))}
		if name == "severity" {
			row.Constant = "unknown"
		}
		if entity == "event" && name == "type" {
			row.Constant = "security_event"
		}
		out = append(out, row)
	}
	return out
}

// Build constructs the same typed config as the API. The form has no credential
// value, tenant, status, destination-email or executable-expression input.
func Build(v url.Values) (config.Config, []config.Issue) {
	issues := []config.Issue{}
	add := func(k, m string) { issues = append(issues, config.Issue{Field: k, Message: m}) }
	allowed := map[string]bool{}
	for _, k := range []string{"csrf_token", "entity", "id", "name", "vendor", "url", "port", "auth_type", "secret_name", "auth_header", "username", "token_url", "client_id", "scopes", "items_path", "query_params", "pagination_type", "page_param", "offset_param", "size_param", "page_size", "cursor_param", "cursor_path", "schedule_enabled", "interval_seconds", "notifications_enabled", "failure_threshold", "cooldown_seconds", "incremental_enabled", "start_time", "since_param", "until_param", "updated_at_path", "overlap_seconds", "safety_lag_seconds"} {
		allowed[k] = true
	}
	entity := v.Get("entity")
	rows := MappingRows(entity)
	for _, r := range rows {
		for _, prefix := range []string{"path_", "constant_", "transform_", "required_", "format_", "timezone_", "precision_", "lookup_"} {
			allowed[prefix+r.Name] = true
		}
	}
	for k, values := range v {
		if !allowed[k] || len(values) != 1 {
			add("form", "unknown or duplicate form field")
		}
	}
	integer := func(k string, def int) int {
		if v.Get(k) == "" {
			return def
		}
		n, e := strconv.Atoi(v.Get(k))
		if e != nil {
			add(k, "enter a whole number")
			return def
		}
		return n
	}
	c := config.Config{Version: 1, ID: v.Get("id"), Name: v.Get("name"), Vendor: v.Get("vendor"), Request: engine.Request{Method: "GET", URL: v.Get("url"), TimeoutSeconds: 20, AllowedPorts: []int{integer("port", 443)}}, Auth: engine.Auth{Type: v.Get("auth_type")}, ItemsPath: v.Get("items_path"), Pagination: engine.Pagination{Type: v.Get("pagination_type")}, Schedule: config.Schedule{Enabled: v.Get("schedule_enabled") == "on", IntervalSeconds: integer("interval_seconds", 900)}, Destination: config.Destination{Entity: entity, Mapping: map[string]config.Field{}}}
	if c.Auth.Type != "none" {
		c.Auth.Secret = v.Get("secret_name")
	}
	switch c.Auth.Type {
	case "api_key":
		c.Auth.Header = v.Get("auth_header")
	case "basic":
		c.Auth.Username = v.Get("username")
	case "oauth2_client_credentials":
		c.Auth.TokenURL = v.Get("token_url")
		c.Auth.ClientID = v.Get("client_id")
		c.Auth.Scopes = strings.Fields(v.Get("scopes"))
	}
	for _, line := range strings.Split(v.Get("query_params"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, val, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) == "" {
			add("query_params", "use one name=value pair per line")
			continue
		}
		if c.Request.Params == nil {
			c.Request.Params = map[string]string{}
		}
		k = strings.TrimSpace(k)
		if _, exists := c.Request.Params[k]; exists {
			add("query_params", "duplicate parameter name")
		}
		c.Request.Params[k] = val
	}
	switch c.Pagination.Type {
	case "page":
		c.Pagination.PageParam = v.Get("page_param")
		c.Pagination.StartPage = 1
		c.Pagination.SizeParam = v.Get("size_param")
		c.Pagination.PageSize = integer("page_size", 100)
	case "offset":
		c.Pagination.OffsetParam = v.Get("offset_param")
		c.Pagination.SizeParam = v.Get("size_param")
		c.Pagination.PageSize = integer("page_size", 100)
	case "cursor":
		c.Pagination.CursorParam = v.Get("cursor_param")
		c.Pagination.CursorPath = v.Get("cursor_path")
		c.Pagination.SizeParam = v.Get("size_param")
		c.Pagination.PageSize = integer("page_size", 100)
	}
	for _, row := range rows {
		path, constant := v.Get("path_"+row.Name), v.Get("constant_"+row.Name)
		if path == "" && constant == "" {
			continue
		}
		field := config.Field{Transform: v.Get("transform_" + row.Name), Required: row.Required || v.Get("required_"+row.Name) == "on", Format: v.Get("format_" + row.Name), Timezone: v.Get("timezone_" + row.Name)}
		if path != "" {
			field.Path = &path
		}
		if constant != "" {
			field.Constant = constant
		}
		if v.Get("precision_"+row.Name) == "on" {
			field.Precision = "date"
		}
		if field.Transform == "lookup" {
			raw := []byte(v.Get("lookup_" + row.Name))
			if config.CheckJSON(raw) != nil || json.Unmarshal(raw, &field.Lookup) != nil {
				add("destination.mapping."+row.Name+".lookup", "enter a JSON object of string replacements")
			}
		}
		c.Destination.Mapping[row.Name] = field
	}
	if v.Get("notifications_enabled") == "on" {
		c.Notifications = &config.Notifications{Enabled: true, FailureThreshold: integer("failure_threshold", 3), CooldownSeconds: integer("cooldown_seconds", 3600)}
	}
	if v.Get("incremental_enabled") == "on" {
		c.Incremental = &config.Incremental{Type: "time_window", StartTime: v.Get("start_time"), SinceParam: v.Get("since_param"), UntilParam: v.Get("until_param"), UpdatedAtPath: v.Get("updated_at_path"), OverlapSeconds: integer("overlap_seconds", 60), SafetyLagSeconds: integer("safety_lag_seconds", 5)}
	}
	c.Defaults()
	issues = append(issues, c.Validate()...)
	return c, issues
}
