package app

import (
	"configbridge/internal/ai"
	"testing"
)

func TestSIEMOptInAndConfiguration(t *testing.T) {
	values := map[string]string{}
	get := func(k string) string { return values[k] }
	if s, e := SIEM(get, nil); e != nil || s != nil {
		t.Fatal("enabled without opt-in")
	}
	values = map[string]string{"CB_SIEM_ENABLED_TENANTS": "tenant-a", "CB_ENV": "dev", "CB_OPENSEARCH_URL": "http://127.0.0.1:50920"}
	model := ai.New("SYNTHETIC_PROVIDER_KEY", "m")
	model.DailyLimit, model.TokenLimit = 5, 50000
	s, e := SIEM(get, model)
	if e != nil || !s.EnabledTenants["tenant-a"] || s.EnabledTenants["tenant-b"] || s.Provider == nil || s.DailyCalls != 5 || s.DailyTokens != 50000 {
		t.Fatal(e)
	}
	if s, e = SIEM(get, nil); e != nil || s.Provider != nil {
		t.Fatal("explanations enabled without an AI provider")
	}
	for _, setting := range [][2]string{{"CB_ENV", "prod"}, {"CB_OPENSEARCH_URL", "http://example.com"}, {"CB_SIEM_ENABLED_TENANTS", "tenant-a,../b"}, {"CB_OPENSEARCH_CA_FILE", "missing-test-ca.pem"}} {
		before := values[setting[0]]
		values[setting[0]] = setting[1]
		if _, e := SIEM(get, model); e == nil {
			t.Fatal("invalid setting accepted", setting[0])
		}
		values[setting[0]] = before
	}
}
