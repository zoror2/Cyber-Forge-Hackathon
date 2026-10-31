package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestStrictJSONAndSharedContract(t *testing.T) {
	b, e := os.ReadFile("../../configs/fixture_events.json")
	if e != nil {
		t.Fatal(e)
	}
	c, issues := Decode(b)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	if e = c.Connector("tenant-a").Validate(); e != nil {
		t.Fatal(e)
	}
	for name, body := range map[string]string{
		"tenant":        strings.Replace(string(b), `"version":1`, `"tenant_id":"tenant-b","version":1`, 1),
		"unknown":       strings.Replace(string(b), `"version":1`, `"execute":"SENTINEL","version":1`, 1),
		"duplicate":     strings.Replace(string(b), `"version":1`, `"version":1,"version":2`, 1),
		"trailing":      string(b) + `{}`,
		"yaml":          "version: 1",
		"secret_header": strings.Replace(string(b), `"method":"GET"`, `"headers":{"Authorization":"SENTINEL"},"method":"GET"`, 1),
		"secret_param":  strings.Replace(string(b), `"method":"GET"`, `"params":{"apiKey":"SENTINEL"},"method":"GET"`, 1),
		"http":          strings.Replace(string(b), "https://", "http://", 1),
		"secret_url":    strings.Replace(string(b), "https://fixture.invalid/events", "https://user:SENTINEL@fixture.invalid/events", 1),
		"timezone":      strings.Replace(string(b), `"UTC"`, `"Nope/Nope"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, issues := Decode([]byte(body))
			if len(issues) == 0 {
				t.Fatal("invalid config accepted")
			}
			raw, _ := json.Marshal(issues)
			if strings.Contains(string(raw), "SENTINEL") {
				t.Fatal("input echoed")
			}
		})
	}
	c.Auth.Type = "bearer"
	if len(c.Validate()) == 0 {
		t.Fatal("missing secret accepted")
	}
	c.Auth.Type = "none"
	c.Pagination.Type = "offset"
	if len(c.Validate()) == 0 {
		t.Fatal("missing paging fields accepted")
	}
}
