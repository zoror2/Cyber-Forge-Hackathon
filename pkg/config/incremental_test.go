package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestIncrementalConfigValidation(t *testing.T) {
	b, err := os.ReadFile("../../configs/mock_users.json")
	if err != nil {
		t.Fatal(err)
	}
	base, issues := Decode(b)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	valid := func() Config {
		c := base
		c.Incremental = &Incremental{Type: "time_window", StartTime: "2026-01-01T00:00:00Z", SinceParam: "updated_since", UntilParam: "updated_before", UpdatedAtPath: "metadata.updated_at", OverlapSeconds: 60, SafetyLagSeconds: 5}
		return c
	}
	c := valid()
	raw, _ := json.Marshal(c)
	if _, issues = Decode(raw); len(issues) > 0 {
		t.Fatal(issues)
	}
	for name, change := range map[string]func(*Config){
		"unsupported type":       func(c *Config) { c.Incremental.Type = "guess" },
		"naive start":            func(c *Config) { c.Incremental.StartTime = "2026-01-01" },
		"missing timestamp":      func(c *Config) { c.Incremental.UpdatedAtPath = "" },
		"invalid path":           func(c *Config) { c.Incremental.UpdatedAtPath = "metadata..updated" },
		"duplicate bounds":       func(c *Config) { c.Incremental.UntilParam = c.Incremental.SinceParam },
		"param conflict":         func(c *Config) { c.Incremental.SinceParam = c.Pagination.PageParam },
		"static filter conflict": func(c *Config) { c.Request.Params = map[string]string{"updated_since": "something"} },
		"secret param":           func(c *Config) { c.Incremental.SinceParam = "apiKey" },
		"unsafe param":           func(c *Config) { c.Incremental.UntilParam = "x&api_key" },
		"negative overlap":       func(c *Config) { c.Incremental.OverlapSeconds = -1 },
		"excess overlap":         func(c *Config) { c.Incremental.OverlapSeconds = 86401 },
		"negative lag":           func(c *Config) { c.Incremental.SafetyLagSeconds = -1 },
		"excess lag":             func(c *Config) { c.Incremental.SafetyLagSeconds = 3601 },
		"unsupported link":       func(c *Config) { c.Pagination.Type = "link" },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid()
			change(&c)
			if len(c.Validate()) == 0 {
				t.Fatal("invalid incremental setting accepted")
			}
		})
	}
	// Unknown fields cannot sneak a caller-selected checkpoint into the config.
	raw = append([]byte(nil), raw...)
	bad := strings.Replace(string(raw), `"type":"time_window"`, `"type":"time_window","watermark":"2099-01-01T00:00:00Z"`, 1)
	if _, issues = Decode([]byte(bad)); len(issues) == 0 {
		t.Fatal("user checkpoint accepted")
	}
}
