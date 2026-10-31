package app

import (
	"testing"
)

func TestSIEMOptInAndConfiguration(t *testing.T) {
	values := map[string]string{}
	get := func(k string) string { return values[k] }
	if s, e := SIEM(get); e != nil || s != nil {
		t.Fatal("enabled without opt-in")
	}
	values = map[string]string{"CB_SIEM_ENABLED_TENANTS": "tenant-a", "CB_ENV": "dev", "CB_OPENSEARCH_URL": "http://127.0.0.1:50920", "GROQ_API_KEY": "SYNTHETIC_PROVIDER_KEY"}
	s, e := SIEM(get)
	if e != nil || !s.EnabledTenants["tenant-a"] || s.EnabledTenants["tenant-b"] {
		t.Fatal(e)
	}
	for _, setting := range [][2]string{{"CB_ENV", "prod"}, {"CB_OPENSEARCH_URL", "http://example.com"}, {"CB_SIEM_ENABLED_TENANTS", "tenant-a,../b"}, {"CB_AI_DAILY_TOKEN_LIMIT", "1"}, {"CB_OPENSEARCH_CA_FILE", "missing-test-ca.pem"}} {
		before := values[setting[0]]
		values[setting[0]] = setting[1]
		if _, e := SIEM(get); e == nil {
			t.Fatal("invalid setting accepted", setting[0])
		}
		values[setting[0]] = before
	}
}
