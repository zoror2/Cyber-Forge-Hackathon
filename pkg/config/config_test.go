package config

import (
	"os"
	"strings"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	b, err := os.ReadFile("../../configs/fixture_events.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, issues := Decode(b)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	if c.ID != "fixture_events" {
		t.Fatal(c.ID)
	}
	cases := map[string]string{
		"custom_tag":        strings.Replace(string(b), "name: Offline four-record demonstration", "name: !execute something", 1),
		"duplicate":         string(b) + "\nversion: 1\n",
		"unknown":           string(b) + "\nexecute: anything\n",
		"multi":             string(b) + "\n---\nversion: 1",
		"private":           strings.Replace(string(b), "https://fixture.invalid/events", "https://169.254.169.254/latest/meta-data", 1),
		"http":              strings.Replace(string(b), "https://fixture.invalid/events", "http://fixture.invalid/events", 1),
		"credential_url":    strings.Replace(string(b), "https://fixture.invalid/events", "https://user:password@fixture.invalid/events", 1),
		"missing_id":        strings.Replace(string(b), "    id:", "    source:", 1),
		"unknown_transform": strings.Replace(string(b), "transform: string", "transform: execute", 1),
		"unknown_timezone":  strings.Replace(string(b), "timezone: UTC", "timezone: Nope/Nope", 1),
		"old_python_layout": strings.Replace(string(b), "2006-01-02", "%Y-%m-%d", 1),
		"secret_param":      strings.Replace(string(b), "params: {}", "params: {api_key: SENTINEL}", 1),
		"secret_header":     strings.Replace(string(b), "Accept: application/json", "Authorization: SENTINEL", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, issues := Decode([]byte(body))
			if len(issues) == 0 {
				t.Fatal("invalid config accepted")
			}
			for _, i := range issues {
				if strings.Contains(i.Error(), "SENTINEL") {
					t.Fatal("secret leaked in error")
				}
			}
		})
	}
}
func TestRequiredAuthAndPaging(t *testing.T) {
	b, _ := os.ReadFile("../../configs/fixture_events.yaml")
	c, _ := Decode(b)
	c.Auth = Auth{Type: "bearer"}
	if len(c.Validate()) == 0 {
		t.Fatal("missing secret accepted")
	}
	c.Auth = Auth{Type: "none"}
	c.Pagination = Pagination{Type: "offset"}
	if len(c.Validate()) == 0 {
		t.Fatal("missing pagination fields accepted")
	}
	c.Pagination = Pagination{Type: "offset", OffsetParam: "startIndex", LimitParam: "resultsPerPage", PageSize: 20}
	if issues := c.Validate(); len(issues) > 0 {
		t.Fatal(issues)
	}
}
