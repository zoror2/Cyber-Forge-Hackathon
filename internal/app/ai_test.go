package app

import (
	"testing"
)

func TestDraftingStartupPolicy(t *testing.T) {
	env := map[string]string{"GROQ_API_KEY": "SYNTHETIC-TEST-KEY-ONLY", "CB_AI_SOURCES_DIR": "../../public_sources"}
	get := func(k string) string { return env[k] }
	if d, e := Drafting(get); e != nil || d != nil {
		t.Fatal("key alone enabled AI")
	}
	env["CB_AI_ENABLED_TENANTS"] = "tenant-a"
	if d, e := Drafting(get); e != nil || !d.EnabledTenants["tenant-a"] || d.EnabledTenants["tenant-b"] {
		t.Fatal("invalid tenant enablement", e)
	}
	for name, value := range map[string]string{"CB_AI_ENABLED_TENANTS": "*", "CB_AI_DAILY_LIMIT": "101", "GROQ_API_KEY": "", "CB_AI_SOURCES_DIR": "missing", "CB_AI_MODEL": "bad model\r\n"} {
		old := env[name]
		env[name] = value
		if _, e := Drafting(get); e == nil {
			t.Fatalf("invalid %s accepted", name)
		}
		env[name] = old
	}
}
