package tests

import (
	"configbridge/internal/engine"
	"encoding/json"
	"strings"
	"testing"
)

// POST /configs/check: same validator as POST /configs, nothing saved,
// returns the credential the pasted config needs.
func TestConfigCheckValidatesWithoutSaving(t *testing.T) {
	e := setup(t)
	c := userConfig("pasted_users", "https://your-tenant.okta.com/api/v1/users")
	c.Vendor = "Okta"
	c.Auth = engine.Auth{Type: "oauth2_client_credentials", Secret: "okta_client", TokenURL: "https://your-tenant.okta.com/oauth2/v1/token"}
	body, _ := json.Marshal(c)
	out := e.request(t, "tenant-a", "POST", "/configs/check", body, 200)
	var got struct {
		Config     map[string]any         `json:"config"`
		Credential *engine.CredentialSpec `json:"credential"`
	}
	if json.Unmarshal(out, &got) != nil || got.Config["vendor"] != "Okta" || got.Credential == nil ||
		got.Credential.Secret != "okta_client" || strings.Join(got.Credential.Fields, ",") != "client_id,client_secret" {
		t.Fatal(string(out))
	}
	if list := e.request(t, "tenant-a", "GET", "/configs", nil, 200); strings.Contains(string(list), "pasted_users") {
		t.Fatal("check saved the config")
	}
	e.request(t, "tenant-a", "POST", "/configs/check", []byte(`{"version":1,"id":"x","tenant_id":"tenant-b"}`), 422)
	e.request(t, "tenant-a", "POST", "/configs/check", []byte(`not json`), 422)
}
