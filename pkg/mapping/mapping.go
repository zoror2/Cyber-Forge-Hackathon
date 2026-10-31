// Package mapping converts provider JSON into exact common record schemas.
package mapping

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/config"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/model"
)

func Path(value any, path string) (any, bool) {
	if path == "" {
		return value, true
	}
	for _, part := range strings.Split(path, ".") {
		switch v := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = v[part]
			if !ok {
				return nil, false
			}
		case []any:
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || n >= len(v) {
				return nil, false
			}
			value = v[n]
		default:
			return nil, false
		}
	}
	return value, true
}
func Items(payload any, path string) ([]any, error) {
	v, ok := Path(payload, path)
	if !ok {
		return nil, fmt.Errorf("collection_path_missing")
	}
	rows, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("collection_not_array")
	}
	return rows, nil
}
func transform(v any, s config.Field) (any, error) {
	switch s.Transform {
	case "", "lookup":
		if s.Transform == "lookup" {
			if replacement, ok := s.Lookup[fmt.Sprint(v)]; ok {
				return replacement, nil
			}
			return nil, fmt.Errorf("unmapped lookup value")
		}
		return v, nil
	case "string":
		switch v.(type) {
		case string, bool, float64, int, int64, json.Number:
			return fmt.Sprint(v), nil
		}
		return nil, fmt.Errorf("scalar required")
	case "integer":
		n, e := strconv.ParseInt(fmt.Sprint(v), 10, 64)
		return n, e
	case "datetime":
		text, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("date string required")
		}
		if s.Format == "" {
			if t, e := time.Parse(time.RFC3339Nano, text); e == nil {
				return t.UTC(), nil
			}
			if s.Timezone == "" {
				return nil, fmt.Errorf("naive date needs timezone")
			}
		}
		loc := time.UTC
		if s.Timezone != "" {
			var err error
			loc, err = time.LoadLocation(s.Timezone)
			if err != nil {
				return nil, err
			}
		}
		layouts := []string{s.Format}
		if s.Format == "" {
			layouts = []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"}
		}
		for _, layout := range layouts {
			// Layouts without a zone cannot inherit the laptop's timezone.
			zoned := strings.Contains(layout, "Z07") || strings.Contains(layout, "-07") || strings.Contains(layout, "MST")
			if !zoned && s.Timezone == "" {
				continue
			}
			if t, e := time.ParseInLocation(layout, text, loc); e == nil {
				return t.UTC(), nil
			}
		}
		return nil, fmt.Errorf("invalid date or missing timezone")
	}
	return nil, fmt.Errorf("unknown transform")
}
func Map(row any, c config.Config, fetched time.Time, index int) (model.Record, *model.Rejection) {
	bad := func(field, reason string) (model.Record, *model.Rejection) {
		return model.Record{}, &model.Rejection{Index: index, Field: field, Reason: reason}
	}
	if _, ok := row.(map[string]any); !ok {
		return bad("record", "must be a JSON object")
	}
	values := map[string]any{}
	for _, name := range config.Fields[c.Destination.Entity] {
		values[name] = nil
	}
	for name, spec := range c.Destination.Mapping {
		v := spec.Constant
		if spec.Path != nil {
			v, _ = Path(row, *spec.Path)
		}
		if v == nil {
			if spec.Required {
				return bad(name, "required value is missing")
			}
			v = spec.Default
		}
		if v != nil {
			var err error
			v, err = transform(v, spec)
			if err != nil {
				return bad(name, "value cannot be converted with configured transform")
			}
		}
		values[name] = v
	}
	id, ok := values["id"].(string)
	if !ok || strings.TrimSpace(id) == "" || len(id) > 512 {
		return bad("id", "nonempty string ID (at most 512 bytes) required")
	}
	values["source"] = c.ID
	values["fetched_at"] = fetched.UTC()
	// Optional timestamps still require explicit conversion and timezone rules.
	for _, name := range []string{"timestamp", "last_login", "last_seen"} {
		if v, exists := values[name]; exists && v != nil {
			if _, ok := v.(time.Time); !ok {
				return bad(name, "configure the datetime transform")
			}
		}
	}
	if c.Destination.Entity == "event" {
		for _, field := range []string{"type", "description"} {
			v, ok := values[field].(string)
			if !ok || strings.TrimSpace(v) == "" {
				return bad(field, "nonempty string required")
			}
		}
		if values["timestamp"] == nil {
			return bad("timestamp", "timestamp is required")
		}
		if values["severity"] == nil {
			values["severity"] = "unknown"
		}
		switch values["severity"] {
		case "critical", "high", "medium", "low", "info", "unknown":
		default:
			return bad("severity", "unsupported severity")
		}
		if c.Destination.Mapping["timestamp"].Precision == "date" {
			values["timestamp_precision"] = "date"
		}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return bad("record", "invalid normalized value")
	}
	// Typed models reject numbers/objects in string fields and establish exact schemas.
	var normalized any
	switch c.Destination.Entity {
	case "user":
		normalized = &model.User{}
	case "device":
		normalized = &model.Device{}
	case "event":
		normalized = &model.Event{}
	default:
		return bad("entity", "unsupported entity")
	}
	if err = json.Unmarshal(raw, normalized); err != nil {
		return bad("record", "normalized field has an invalid type")
	}
	raw, err = json.Marshal(normalized)
	if err != nil {
		return bad("record", "cannot encode normalized record")
	}
	return model.Record{Entity: c.Destination.Entity, ID: id, Source: c.ID, FetchedAt: fetched.UTC(), Payload: raw}, nil
}
