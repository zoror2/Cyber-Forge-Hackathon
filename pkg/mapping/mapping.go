// Package mapping turns one vendor record into one OCSF event (the common schema),
// and decides which vendor records a config's filter keeps.
package mapping

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"configbridge/pkg/config"
	"configbridge/pkg/jsonvalue"
	"configbridge/pkg/model"
	"configbridge/pkg/ocsf"
)

func Path(value any, path string) (any, bool) {
	return jsonvalue.Path(value, path)
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
	case "trim":
		text, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("string required")
		}
		return strings.TrimSpace(text), nil
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

// Keep reports whether a vendor record passes every filter condition (AND).
// A missing field fails every condition except exists:false.
func Keep(row any, filters []config.Condition, now time.Time) bool {
	for _, f := range filters {
		v, found := Path(row, f.Path)
		found = found && v != nil
		switch f.Op {
		case "exists":
			want := f.Value != false
			if found != want {
				return false
			}
		case "equals":
			if !found || fmt.Sprint(v) != fmt.Sprint(f.Value) {
				return false
			}
		case "not_equals":
			if found && fmt.Sprint(v) == fmt.Sprint(f.Value) {
				return false
			}
		case "in":
			list, _ := f.Value.([]any)
			hit := false
			for _, x := range list {
				if found && fmt.Sprint(v) == fmt.Sprint(x) {
					hit = true
					break
				}
			}
			if !hit {
				return false
			}
		case "within_days":
			days, err := json.Number(fmt.Sprint(f.Value)).Int64()
			text, ok := v.(string)
			if err != nil || !found || !ok {
				return false
			}
			t, err := time.Parse(time.RFC3339Nano, text)
			if err != nil {
				t, err = time.Parse("2006-01-02", text)
			}
			if err != nil || t.Before(now.AddDate(0, 0, -int(days))) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// Map converts one vendor record into one OCSF event. Any problem becomes a
// Rejection naming the OCSF field; the record is quarantined, the run continues.
func Map(row any, c config.Config, tenant string, fetched time.Time, index int) (model.Record, *model.Rejection) {
	bad := func(field, reason string) (model.Record, *model.Rejection) {
		return model.Record{}, &model.Rejection{Index: index, Field: field, Reason: reason}
	}
	if _, ok := row.(map[string]any); !ok {
		return bad("record", "must be a JSON object")
	}
	if !config.ValidID(tenant) {
		return bad("tenant_id", "trusted tenant identity is required")
	}
	class, ok := ocsf.Lookup(c.Destination.Class)
	if !ok {
		return bad("destination.class", "unsupported OCSF class")
	}
	values := map[string]any{}
	// Fixed order so a bad record always reports the same field: identity first, then sorted.
	identity := ocsf.Identity[c.Destination.Class]
	order := make([]string, 0, len(c.Destination.Mapping))
	for path := range c.Destination.Mapping {
		order = append(order, path)
	}
	sort.Slice(order, func(i, j int) bool {
		if (order[i] == identity) != (order[j] == identity) {
			return order[i] == identity
		}
		return order[i] < order[j]
	})
	for _, path := range order {
		spec := c.Destination.Mapping[path]
		v := spec.Constant
		if spec.Path != nil {
			v, _ = Path(row, *spec.Path)
		}
		if v == nil {
			if spec.Required {
				return bad(path, "required value is missing")
			}
			v = spec.Default
		}
		if v == nil {
			continue // optional and absent: the OCSF field is simply not set
		}
		v, err := transform(v, spec)
		if err != nil {
			return bad(path, "value cannot be converted with configured transform")
		}
		attr, err := ocsf.Resolve(class, path)
		if err != nil {
			return bad(path, "not a mappable OCSF field")
		}
		if v, err = ocsf.Coerce(attr, v); err != nil {
			return bad(path, "value does not fit OCSF type: "+err.Error())
		}
		values[path] = v
	}
	product := c.Name
	doc, err := ocsf.Build(class, values, ocsf.Context{Tenant: tenant, Source: c.ID, Product: product, Fetched: fetched.UTC(), ActivityID: c.Destination.ActivityID})
	if err != nil {
		var fe *ocsf.FieldError
		if errors.As(err, &fe) {
			return bad(fe.Field, fe.Reason)
		}
		return bad("record", "not a valid OCSF event")
	}
	id, ok := ocsf.Get(doc, ocsf.Identity[class.Name]).(string)
	if !ok || strings.TrimSpace(id) == "" || len(id) > 512 {
		return bad(ocsf.Identity[class.Name], "nonempty string ID (at most 512 bytes) required")
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return bad("record", "cannot encode OCSF event")
	}
	return model.Record{TenantID: tenant, Class: class.Name, ClassUID: class.UID, ID: id, Source: c.ID, FetchedAt: fetched.UTC(), Payload: raw}, nil
}
