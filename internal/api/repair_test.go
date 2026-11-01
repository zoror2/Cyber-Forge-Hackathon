package api

import (
	"configbridge/internal/engine"
	"configbridge/pkg/config"
	"testing"
)

func TestRepairCandidatesPreserveMeaningAndRefuseGuesses(t *testing.T) {
	path := func(s string) *string { return &s }
	base := config.Config{Version: 1, ID: "repair", Name: "Synthetic", Request: engine.Request{URL: "https://example.com/users"}, Destination: config.Destination{Class: "user_inventory", Mapping: map[string]config.Field{"user.uid": {Path: path("id"), Required: true}, "user.name": {Path: path("name"), Required: true, Transform: "integer"}}}}
	base.Defaults()
	for _, tc := range []struct {
		name string
		rows []any
		want bool
	}{
		{"conversion", []any{map[string]any{"id": "1", "name": "Alice"}}, true},
		{"missing", []any{map[string]any{"id": "1"}}, false},
		{"object", []any{map[string]any{"id": "1", "name": map[string]any{"nested": "Alice"}}}, false},
		{"preserve_valid", []any{map[string]any{"id": "1", "name": "007"}, map[string]any{"id": "2", "name": "Alice"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := repairCandidates(base, tc.rows, "tenant-a")
			if (len(got) > 0) != tc.want {
				t.Fatalf("candidates=%d want exists %v", len(got), tc.want)
			}
			for _, c := range got {
				if *c.config.Destination.Mapping["user.name"].Path != "name" || !c.config.Destination.Mapping["user.name"].Required || c.config.Request.URL != base.Request.URL {
					t.Fatal("changed mapping contract")
				}
			}
		})
	}
	delete(base.Destination.Mapping, "user.name")
	base.Destination.Mapping["user.ldap_person.last_login_time"] = config.Field{Path: path("at"), Transform: "string"}
	for _, tc := range []struct {
		value string
		want  bool
	}{{"2026-11-01T10:30:00+05:30", true}, {"2026-11-01", false}, {"not-a-date", false}} {
		if got := repairCandidates(base, []any{map[string]any{"id": "1", "at": tc.value}}, "tenant-a"); (len(got) > 0) != tc.want {
			t.Fatalf("date %q: %d candidates", tc.value, len(got))
		}
	}
	base.Destination.Mapping["user.uid"] = config.Field{Path: path("id"), Required: true, Transform: "integer"}
	if got := repairCandidates(base, []any{map[string]any{"id": "abc"}}, "tenant-a"); len(got) != 0 {
		t.Fatal("identity mapping automatically changed")
	}
}
