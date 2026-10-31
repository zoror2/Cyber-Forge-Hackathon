package config

import (
	"maps"
	"regexp"
	"strings"
	"time"
)

func (c Config) validateIncremental() []Issue {
	out := []Issue{}
	if c.Incremental == nil {
		return out
	}
	i := c.Incremental
	add := func(field, message string) { out = append(out, Issue{"incremental." + field, message}) }
	if i.Type != "time_window" {
		add("type", "must be time_window")
	}
	start, err := time.Parse(time.RFC3339Nano, i.StartTime)
	if err != nil || start.Year() < 1970 || start.Year() > 9998 {
		add("start_time", "must be an RFC3339 timestamp with timezone, year 1970-9998")
	}
	param := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)
	for _, p := range []struct{ field, name string }{{"since_param", i.SinceParam}, {"until_param", i.UntilParam}} {
		if !param.MatchString(p.name) {
			add(p.field, "must be a query parameter name, 1-64 letters/digits/underscores")
		}
		for k := range c.Request.Params {
			if strings.EqualFold(k, p.name) {
				add(p.field, "must not also appear in request.params")
			}
		}
		for _, k := range []string{c.Pagination.PageParam, c.Pagination.OffsetParam, c.Pagination.SizeParam, c.Pagination.CursorParam} {
			if k != "" && strings.EqualFold(k, p.name) {
				add(p.field, "must not overwrite pagination parameters")
			}
		}
	}
	if strings.EqualFold(i.SinceParam, i.UntilParam) {
		add("until_param", "must differ from since_param")
	}
	if len(i.UpdatedAtPath) > 256 || !regexp.MustCompile(`^[A-Za-z0-9_@-]+(\.[A-Za-z0-9_@-]+)*$`).MatchString(i.UpdatedAtPath) {
		add("updated_at_path", "must be a nonempty dotted path to an RFC3339 modification timestamp")
	}
	if i.OverlapSeconds < 0 || i.OverlapSeconds > 86400 {
		add("overlap_seconds", "must be 0-86400")
	}
	if i.SafetyLagSeconds < 0 || i.SafetyLagSeconds > 3600 {
		add("safety_lag_seconds", "must be 0-3600")
	}
	switch c.Pagination.Type {
	case "none", "page", "offset":
	default:
		add("type", "time_window currently supports none/page/offset with stable filtered pagination")
	}
	// Validate generated parameters against the same credential-name restrictions
	// as normal requests. This must not introduce a secret-in-query escape hatch.
	probe := c.Connector("validation")
	probe.Request.Params = maps.Clone(c.Request.Params)
	if probe.Request.Params == nil {
		probe.Request.Params = map[string]string{}
	}
	probe.Request.Params[i.SinceParam] = "2020-01-01T00:00:00Z"
	probe.Request.Params[i.UntilParam] = "2020-01-02T00:00:00Z"
	if probe.Validate() != nil && c.Connector("validation").Validate() == nil {
		add("since_param", "generated filter parameters must pass request-side security validation")
	}
	return out
}
