package tests

import (
	"bytes"
	"configbridge/internal/api"
	"configbridge/internal/insights"
	"configbridge/internal/store"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// Multiple keys identify principals, not separate customers or AI budgets.
// This runs the real API/authentication, engine and PostgreSQL ledger. With
// TEST_OPENSEARCH_URL it also uses the real Docker OpenSearch service.
func TestMultipleCustomerKeysShareUsageAndRemainIsolated(t *testing.T) {
	e := setup(t)
	var search insights.Search = &findingSearch{}
	if endpoint := os.Getenv("TEST_OPENSEARCH_URL"); endpoint != "" {
		var err error
		search, err = insights.NewSearch(endpoint, "", "", "dev", e.db.Schema, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("Using real Docker OpenSearch and PostgreSQL")
	}
	provider := &explanationProvider{}
	h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc, Limits: &api.Limits{},
		OperatorToken: strings.Repeat("synthetic-platform-", 3),
		SIEM:          &api.SIEM{Search: search, Provider: provider, EnabledTenants: map[string]bool{"tenant-a": true, "tenant-b": true}, DailyCalls: 2, DailyTokens: 400000}})
	if err != nil {
		t.Fatal(err)
	}
	e.api.Close()
	e.api = httptest.NewServer(h)
	t.Cleanup(e.api.Close)
	request := func(token, method, path string, body []byte, want int) ([]byte, error) {
		r, err := http.NewRequest(method, e.api.URL+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-Tenant-ID", "tenant-b") // never authoritative, even with a valid A key
		r.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		if err != nil {
			return nil, err
		}
		if response.StatusCode != want {
			return nil, fmt.Errorf("%s %s: got %d, want %d", method, path, response.StatusCode, want)
		}
		return raw, nil
	}
	call := func(token, method, path string, body []byte, want int) []byte {
		t.Helper()
		raw, err := request(token, method, path, body, want)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	type credential struct{ tenant, user, id, secret, connector string }
	keys := []credential{}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		c := securityConfig(t, e, strings.ReplaceAll(tenant, "-", "_")+"_events")
		e.save(t, tenant, c, true)
		if result := e.run(t, tenant, c.ID, 200); result.Accepted != 9 {
			t.Fatal(result)
		}
		var user store.User
		body, _ := json.Marshal(map[string]string{"name": "Key Test Editor", "email": "editor@keys.test", "role": "editor", "password": pw})
		if err := json.Unmarshal(call(key(tenant), "POST", "/iam/users", body, 201), &user); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			var created struct {
				Secret string    `json:"secret"`
				Key    store.Key `json:"key"`
			}
			if err := json.Unmarshal(call(key(tenant), "POST", "/iam/users/"+user.ID+"/keys", []byte(fmt.Sprintf(`{"name":"client-%d"}`, i)), 201), &created); err != nil || created.Secret == "" {
				t.Fatal("key issuance failed", err)
			}
			keys = append(keys, credential{tenant, user.ID, created.Key.ID, created.Secret, c.ID})
		}
		call(key(tenant), "POST", "/iam/users/"+user.ID+"/keys", []byte(`{"name":"third"}`), 409)
	}
	// Each customer's two keys contribute to the SAME ledger and call quota.
	for _, k := range keys {
		call(k.secret, "POST", "/siem/ask", question(k.connector, "security_findings"), 200)
		call(k.secret, "GET", "/operator/ai/consumption", nil, 401)
	}
	for _, k := range keys {
		raw := call(k.secret, "POST", "/siem/ask", question(k.connector, "security_findings"), 429)
		if !bytes.Contains(raw, []byte("ai_budget_reached")) {
			t.Fatal("shared customer quota was not enforced")
		}
	}
	if provider.calls != 4 {
		t.Fatal("extra model calls or customer quota leaked", provider.calls)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		var audits []store.AIAudit
		if err := json.Unmarshal(call(key(tenant), "GET", "/ai/audit", nil, 200), &audits); err != nil {
			t.Fatal(err)
		}
		actors := map[string]bool{}
		for _, a := range audits {
			if a.Outcome == "requested" {
				actors[a.Actor] = true
			}
		}
		if len(actors) != 2 {
			t.Fatal("requests not attributable to both keys", len(actors))
		}
	}
	// Interleave 24 authenticated reads across four keys and two customers.
	// No test Fatal is called from worker goroutines.
	var wg sync.WaitGroup
	errors := make(chan error, 24)
	for _, k := range keys {
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func(k credential) {
				defer wg.Done()
				body, err := request(k.secret, "GET", "/ai/consumption", nil, 200)
				if err != nil {
					errors <- err
					return
				}
				var r store.AIReport
				if err = json.Unmarshal(body, &r); err != nil {
					errors <- err
					return
				}
				if r.CustomerCount != 1 || len(r.Customers) != 1 || r.Customers[0].Customer != k.tenant || r.Summary.Requests != 2 || r.Summary.ReportedTokens != 240 || r.Summary.UnreportedReserved != 0 {
					errors <- fmt.Errorf("mixed customer usage for %s", k.tenant)
					return
				}
				for _, row := range r.Requests {
					if row.Customer != k.tenant {
						errors <- fmt.Errorf("foreign request in %s", k.tenant)
						return
					}
				}
			}(k)
		}
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	a, b := keys[0], keys[2]
	call(b.secret, "GET", "/configs/"+a.connector, nil, 404)
	call(a.secret, "GET", "/configs/"+b.connector, nil, 404)
	call(b.secret, "PATCH", "/iam/keys/"+a.id, []byte(`{"active":false}`), 404)
	call(a.secret, "GET", "/ai/consumption?customer=tenant-b", nil, 400)
	call(strings.Repeat("invalid-key-", 4), "GET", "/ai/consumption", nil, 401)
	// These keys are already in the API's verification cache: revocation must
	// still be immediate, without disabling the owner's other key.
	call(key("tenant-a"), "PATCH", "/iam/keys/"+a.id, []byte(`{"active":false}`), 204)
	call(a.secret, "GET", "/ai/consumption", nil, 401)
	call(keys[1].secret, "GET", "/ai/consumption", nil, 200)
	call(b.secret, "GET", "/ai/consumption", nil, 200)
	call(key("tenant-a"), "PATCH", "/iam/keys/"+a.id, []byte(`{"active":true}`), 204)
	call(a.secret, "GET", "/ai/consumption", nil, 200)
	// Role changes and owner deactivation affect ALL that user's keys.
	call(key("tenant-a"), "PATCH", "/iam/users/"+a.user, []byte(`{"role":"viewer"}`), 204)
	for _, k := range keys[:2] {
		call(k.secret, "POST", "/siem/ask", question(k.connector, "security_findings"), 403)
		call(k.secret, "GET", "/ai/consumption", nil, 200)
	}
	call(key("tenant-a"), "PATCH", "/iam/users/"+a.user, []byte(`{"active":false}`), 204)
	for _, k := range keys[:2] {
		call(k.secret, "GET", "/ai/consumption", nil, 401)
	}
	for _, k := range keys[2:] {
		call(k.secret, "GET", "/ai/consumption", nil, 200)
	}
	if provider.calls != 4 {
		t.Fatal("read, rejected or unauthorized request called model")
	}
	t.Log("PASS: four customer keys, 24 concurrent reads, shared per-customer quota/usage, separate key actors, foreign ownership denial, immediate revocation, role changes and owner deactivation")
}
