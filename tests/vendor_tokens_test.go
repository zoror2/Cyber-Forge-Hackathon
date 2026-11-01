package tests

import (
	"bytes"
	"configbridge/internal/engine"
	"configbridge/pkg/model"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// GitHub-style bearer auth and Link pagination: two tenants, each with two
// connectors, reusing the same connector/secret names but different PAT values.
// Credentials are synthetic; the TLS vendor verifies the exact token on EVERY
// page, including four deliberately overlapping first-page requests.
func TestConcurrentVendorTokensRemainBoundToTenantAndConnector(t *testing.T) {
	e := setup(t)
	type source struct{ tenant, connector, secret, value string }
	sources := []source{
		{"tenant-a", "repo_one", "github_one", "SYNTHETIC_VENDOR_A_ONE"},
		{"tenant-a", "repo_two", "github_two", "SYNTHETIC_VENDOR_A_TWO"},
		{"tenant-b", "repo_one", "github_one", "SYNTHETIC_VENDOR_B_ONE"},
		{"tenant-b", "repo_two", "github_two", "SYNTHETIC_VENDOR_B_TWO"},
	}
	var mu sync.Mutex
	expected := map[string]string{}
	calls := map[string]int{}
	for _, s := range sources {
		expected["/"+s.tenant+"/"+s.connector] = s.value
	}
	ready := make(chan struct{}, 4)
	release := make(chan struct{})
	var firstBatch atomic.Bool
	firstBatch.Store(true)
	var mismatches atomic.Int32
	vendor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		want, exists := expected[r.URL.Path]
		calls[r.URL.Path]++
		mu.Unlock()
		if !exists {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+want {
			mismatches.Add(1)
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"invalid credential"}`)
			return
		}
		page := r.URL.Query().Get("page")
		if page == "" {
			page = "1"
		}
		if page == "1" && firstBatch.Load() {
			ready <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		if page == "1" {
			w.Header().Set("Link", fmt.Sprintf(`<https://%s%s?page=2>; rel="next"`, r.Host, r.URL.Path))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]any{{"id": page, "profile": map[string]string{"name": r.URL.Path}}})
	}))
	defer vendor.Close()
	e.requests.Policy.RootCAs = vendor.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	u, _ := url.Parse(vendor.URL)
	put := func(s source, value, host string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"value": value, "allowed_host": host})
		e.request(t, s.tenant, "PUT", "/secrets/"+s.secret, body, 204)
	}
	for _, s := range sources {
		put(s, s.value, u.Host)
		c := userConfig(s.connector, vendor.URL+"/"+s.tenant+"/"+s.connector)
		c.Auth = engine.Auth{Type: "bearer", Secret: s.secret}
		c.Pagination = engine.Pagination{Type: "link", SizeParam: "per_page", PageSize: 1}
		c.Request.TimeoutSeconds = 10
		e.save(t, s.tenant, c, true)
	}
	run := func(s source) (model.Run, error) {
		r, err := http.NewRequest("POST", e.api.URL+"/connectors/"+s.connector+"/run", nil)
		if err != nil {
			return model.Run{}, err
		}
		r.Header.Set("Authorization", "Bearer "+key(s.tenant))
		r.Header.Set("X-Tenant-ID", "tenant-b")
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			return model.Run{}, err
		}
		defer response.Body.Close()
		var result model.Run
		if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
			return result, err
		}
		if response.StatusCode != 200 || result.Outcome != "success" || result.Pages != 2 || result.Accepted != 2 || result.TenantID != s.tenant {
			return result, fmt.Errorf("incorrect collection outcome for %s/%s", s.tenant, s.connector)
		}
		return result, nil
	}
	var wg sync.WaitGroup
	errors := make(chan error, 4)
	start := make(chan struct{})
	for _, s := range sources {
		wg.Add(1)
		go func(s source) {
			defer wg.Done()
			<-start
			if _, err := run(s); err != nil {
				errors <- err
			}
		}(s)
	}
	close(start)
	overlapped := 0
	deadline := time.NewTimer(8 * time.Second)
waitReady:
	for overlapped < 4 {
		select {
		case <-ready:
			overlapped++
		case <-deadline.C:
			break waitReady
		}
	}
	deadline.Stop()
	firstBatch.Store(false)
	close(release)
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if overlapped != 4 || mismatches.Load() != 0 {
		t.Fatalf("four vendor calls did not overlap cleanly: started=%d mismatches=%d", overlapped, mismatches.Load())
	}
	for _, s := range sources {
		mu.Lock()
		n := calls["/"+s.tenant+"/"+s.connector]
		mu.Unlock()
		if n != 2 {
			t.Fatal("incorrect authenticated page count", n)
		}
		rows, err := e.db.Store.ForTenant(s.tenant).Records(context.Background(), 5003, s.connector, 100, 0)
		if err != nil || len(rows) != 2 {
			t.Fatal("missing or mixed source records", len(rows), err)
		}
		for _, row := range rows {
			raw, _ := json.Marshal(row)
			if !bytes.Contains(raw, []byte("/"+s.tenant+"/"+s.connector)) {
				t.Fatal("foreign connector payload persisted")
			}
		}
	}
	// Rotate one PAT at the same host. Only its connector changes credentials;
	// all the other tenant/connector tokens must remain valid.
	rotated := "SYNTHETIC_VENDOR_A_ROTATED"
	mu.Lock()
	expected["/tenant-a/repo_one"] = rotated
	mu.Unlock()
	put(sources[0], rotated, u.Host)
	for _, s := range sources {
		if _, err := run(s); err != nil {
			t.Fatal(err)
		}
	}
	if mismatches.Load() != 0 {
		t.Fatal("rotation mixed a different connector's credential")
	}
	// A revoked/invalid PAT fails once, without borrowing another working PAT.
	put(sources[1], "SYNTHETIC_INVALID_PAT", u.Host)
	mu.Lock()
	before := calls["/tenant-a/repo_two"]
	mu.Unlock()
	if r := e.run(t, "tenant-a", "repo_two", 502); r.Error != "auth_failed" {
		t.Fatal("invalid PAT not reported clearly", r.Error)
	}
	mu.Lock()
	after := calls["/tenant-a/repo_two"]
	mu.Unlock()
	if after != before+1 {
		t.Fatal("invalid PAT caused retry storm or silent fallback")
	}
	if _, err := run(sources[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := run(sources[2]); err != nil {
		t.Fatal(err)
	}
	put(sources[1], sources[1].value, u.Host)
	if _, err := run(sources[1]); err != nil {
		t.Fatal(err)
	}
	// Missing and mis-bound references cannot fall back to a different tenant.
	for _, test := range []struct{ name, secret, code string }{{"missing_pat", "only_other_tenant", "credential_missing"}, {"wrong_host_pat", "wrong_host_pat", "credential_binding_mismatch"}} {
		if test.name == "missing_pat" {
			s := sources[2]
			s.secret = test.secret
			put(s, "SYNTHETIC_OTHER_TENANT_ONLY", u.Host)
		} else {
			s := sources[0]
			s.secret = test.secret
			put(s, "SYNTHETIC_WRONG_HOST_PAT", "other.example.com")
		}
		c := userConfig(test.name, vendor.URL+"/tenant-a/repo_one")
		c.Auth = engine.Auth{Type: "bearer", Secret: test.secret}
		e.save(t, "tenant-a", c, true)
		mu.Lock()
		before := calls["/tenant-a/repo_one"]
		mu.Unlock()
		result := e.run(t, "tenant-a", c.ID, 502)
		if result.Error != test.code {
			t.Fatalf("%s got %s want %s", test.name, result.Error, test.code)
		}
		mu.Lock()
		after := calls["/tenant-a/repo_one"]
		mu.Unlock()
		if before != after {
			t.Fatal("unsafe credential reference reached vendor")
		}
	}
	values := []string{rotated, "SYNTHETIC_INVALID_PAT", "SYNTHETIC_OTHER_TENANT_ONLY", "SYNTHETIC_WRONG_HOST_PAT"}
	for _, s := range sources {
		values = append(values, s.value)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		for _, path := range []string{"/secrets", "/runs", "/quarantine"} {
			raw := e.request(t, tenant, "GET", path, nil, 200)
			for _, value := range values {
				if bytes.Contains(raw, []byte(value)) {
					t.Fatal("vendor credential leaked through API")
				}
			}
		}
	}
	for _, value := range values {
		if strings.Contains(e.logs.String(), value) {
			t.Fatal("vendor credential leaked into logs")
		}
	}
	t.Log("PASS: four distinct vendor PATs, overlapping calls, authenticated pagination, tenant/connector isolation, rotation, invalid PAT recovery, no fallback/leakage and host binding")
}
