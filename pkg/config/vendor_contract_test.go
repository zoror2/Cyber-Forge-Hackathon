package config

import (
	"configbridge/internal/engine"
	"os"
	"testing"
)

func TestVendorSettingsRejectMalformedPointersAndChecks(t *testing.T) {
	raw, err := os.ReadFile("../../configs/elastic_security_alerts.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.ItemsPath = "/hits/~invalid" },
		func(c *Config) { p := "/fields/a~2b"; c.Destination.Mapping["finding_info.title"] = Field{Path: &p} },
		func(c *Config) { c.ResponseChecks = []engine.ResponseCheck{{Path: "timed_out", Equals: nil}} },
		func(c *Config) { c.ResponseChecks = []engine.ResponseCheck{{Path: "timed_out", Equals: []any{false}}} },
		func(c *Config) { c.ResponseChecks = []engine.ResponseCheck{{Path: "", Equals: false}} },
		func(c *Config) { c.Pagination = engine.Pagination{Type: "next_url"} },
		func(c *Config) { c.Auth.ClientAuthMethod = "client_secret_post" },
	} {
		cfg, issues := Decode(raw)
		if len(issues) > 0 {
			t.Fatal(issues)
		}
		mutate(&cfg)
		if len(cfg.Validate()) == 0 {
			t.Fatal("invalid vendor setting passed validation")
		}
	}
}
