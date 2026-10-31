package mapping

import (
	"encoding/json"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/config"
	"os"
	"testing"
	"time"
)

func ptr(s string) *string { return &s }
func TestFixtureAndDatePrecision(t *testing.T) {
	b, _ := os.ReadFile("../../configs/fixture_events.yaml")
	c, issues := config.Decode(b)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	raw, _ := os.ReadFile("../../internal/fixture/testdata/events.json")
	var p any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	items, err := Items(p, c.Response.ItemsPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	good, bad := 0, 0
	for i, row := range items {
		r, q := Map(row, c, now, i)
		if q != nil {
			bad++
			if q.Field != "id" {
				t.Fatal(q)
			}
		} else {
			good++
			var payload map[string]any
			json.Unmarshal(r.Payload, &payload)
			if payload["timestamp_precision"] != "date" || payload["source"] != "fixture_events" {
				t.Fatal(payload)
			}
		}
	}
	if good != 3 || bad != 1 {
		t.Fatalf("got %d/%d", good, bad)
	}
}
func TestUserDeviceNestedDefaultsAndZero(t *testing.T) {
	c := config.Config{ID: "source", Destination: config.Destination{Entity: "user", Mapping: map[string]config.Field{
		"id": {Path: ptr("id"), Required: true, Transform: "string"}, "email": {Path: ptr("profile.contacts.0.email")}, "status": {Path: ptr("active"), Transform: "string"}, "name": {Path: ptr("missing"), Default: "anonymous"}, "last_login": {Path: ptr("last"), Transform: "datetime", Format: "02/01/2006 15:04", Timezone: "Asia/Kolkata"},
	}}}
	row := map[string]any{"id": 0, "active": false, "last": "31/10/2026 15:30", "profile": map[string]any{"contacts": []any{map[string]any{"email": "demo@example.invalid"}}}}
	r, q := Map(row, c, time.Now(), 0)
	if q != nil {
		t.Fatal(q)
	}
	var v map[string]any
	json.Unmarshal(r.Payload, &v)
	if v["id"] != "0" || v["status"] != "false" || v["name"] != "anonymous" || v["last_login"] != "2026-10-31T10:00:00Z" {
		t.Fatal(v)
	}
	c.Destination.Entity = "device"
	c.Destination.Mapping = map[string]config.Field{"id": {Constant: "device-1"}}
	r, q = Map(map[string]any{}, c, time.Now(), 0)
	if q != nil {
		t.Fatal(q)
	}
	v = map[string]any{}
	json.Unmarshal(r.Payload, &v)
	if len(v) != 8 || v["owner"] != nil || v["last_seen"] != nil {
		t.Fatal(v)
	}
}
func TestBadRecordsAndCollection(t *testing.T) {
	if _, err := Items(map[string]any{}, "items"); err == nil {
		t.Fatal("missing collection accepted")
	}
	if _, err := Items(map[string]any{"items": "oops"}, "items"); err == nil {
		t.Fatal("non-array accepted")
	}
	if v, err := Items([]any{}, ""); err != nil || len(v) != 0 {
		t.Fatal(err)
	}
	for _, value := range []string{"not-a-date", "2026-10-31T10:00:00"} {
		if _, err := transform(value, config.Field{Transform: "datetime"}); err == nil {
			t.Fatal("invalid or naive date accepted")
		}
	}
	converted, err := transform("2026-10-31T15:30:00+05:30", config.Field{Transform: "datetime"})
	if err != nil || converted.(time.Time).Format(time.RFC3339) != "2026-10-31T10:00:00Z" {
		t.Fatal(converted, err)
	}
	c := config.Config{ID: "test", Destination: config.Destination{Entity: "user", Mapping: map[string]config.Field{"id": {Constant: " "}}}}
	if _, q := Map(map[string]any{}, c, time.Now(), 0); q == nil {
		t.Fatal("blank ID accepted")
	}
}
