package tests

import (
	"configbridge/pkg/config"
	"configbridge/pkg/ocsf"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// Inputs and expected values are checked-in fixtures, independently authored
// from the engine. No LLM or commercial account is involved.
func TestJuryProvidedConfigsAndExactStoredResults(t *testing.T) {
	e := setup(t)
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile("testdata/jury/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var source []json.RawMessage
	if err := json.Unmarshal(read("users_response.json"), &source); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	vendor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if r.Method != "GET" || r.URL.Path != "/users" || err != nil || page < 1 || r.URL.Query().Get("limit") != "2" {
			w.WriteHeader(400)
			return
		}
		start := min((page-1)*2, len(source))
		end := min(start+2, len(source))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"users": source[start:end]}})
	}))
	defer vendor.Close()
	e.requests.Policy.RootCAs = vendor.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	load := func() config.Config {
		t.Helper()
		c, issues := config.Decode(read("users_config.json"))
		if len(issues) > 0 {
			t.Fatal(issues)
		}
		c.Request.URL = vendor.URL + "/users"
		c.Request.AllowedPorts = []int{portOf(vendor.URL)}
		return c
	}
	t.Run("invalid inputs are rejected without outbound calls", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			change func(*config.Config)
			raw    func([]byte) []byte
		}{
			{name: "unsupported POST", change: func(c *config.Config) { c.Request.Method = "POST" }},
			{name: "insecure HTTP", change: func(c *config.Config) { c.Request.URL = strings.Replace(c.Request.URL, "https://", "http://", 1) }},
			{name: "inline credential", change: func(c *config.Config) {
				c.Request.Headers = map[string]string{"Authorization": "JURY_SECRET_MUST_NOT_LEAK"}
			}},
			{name: "missing identity mapping", change: func(c *config.Config) { delete(c.Destination.Mapping, "user.uid") }},
			{name: "unsupported class", change: func(c *config.Config) { c.Destination.Class = "repository_inventory" }},
			{name: "unsupported pagination", change: func(c *config.Config) { c.Pagination.Type = "graphql_relay" }},
			{name: "negative page size", change: func(c *config.Config) { c.Pagination.PageSize = -2 }},
			{name: "bad pointer", change: func(c *config.Config) { c.ItemsPath = "/data/~2users" }},
			{name: "tenant injection", raw: func(b []byte) []byte {
				return []byte(strings.Replace(string(b), `"version":1`, `"tenant_id":"tenant-b","version":1`, 1))
			}},
			{name: "duplicate key", raw: func(b []byte) []byte {
				return []byte(strings.Replace(string(b), `"version":1`, `"version":1,"version":1`, 1))
			}},
			{name: "trailing JSON", raw: func(b []byte) []byte { return append(b, []byte(`{}`)...) }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c := load()
				if tc.change != nil {
					tc.change(&c)
				}
				b, err := json.Marshal(c)
				if err != nil {
					t.Fatal(err)
				}
				if tc.raw != nil {
					b = tc.raw(b)
				}
				out := e.request(t, "tenant-a", "POST", "/configs/check", b, 422)
				if strings.Contains(string(out), "JURY_SECRET_MUST_NOT_LEAK") {
					t.Fatal("secret echoed by validator")
				}
			})
		}
		if calls.Load() != 0 {
			t.Fatal("validation made vendor requests")
		}
		if list := e.request(t, "tenant-a", "GET", "/configs", nil, 200); strings.TrimSpace(string(list)) != "[]" {
			t.Fatal("invalid/check-only configs persisted")
		}
	})
	c := load()
	revision := e.save(t, "tenant-a", c, false)
	e.request(t, "tenant-a", "POST", "/configs/"+c.ID+"/test", []byte(fmt.Sprintf(`{"revision":%d}`, revision)), 200)
	if runs := e.request(t, "tenant-a", "GET", "/runs", nil, 200); strings.TrimSpace(string(runs)) != "[]" {
		t.Fatal("preview wrote a run")
	}
	if records := e.request(t, "tenant-a", "GET", "/records/user_inventory", nil, 200); strings.TrimSpace(string(records)) != "[]" {
		t.Fatal("preview wrote records")
	}
	e.request(t, "tenant-a", "POST", "/configs/"+c.ID+"/activate", []byte(fmt.Sprintf(`{"revision":%d}`, revision)), 200)
	for i := 0; i < 2; i++ {
		run := e.run(t, "tenant-a", c.ID, 200)
		if run.Pages != 3 || run.Received != 4 || run.Accepted != 2 || run.Quarantined != 2 || run.Outcome != "completed_with_errors" {
			t.Fatal("wrong run outcome", run)
		}
	}
	var expected []map[string]any
	if err := json.Unmarshal(read("expected_users.json"), &expected); err != nil {
		t.Fatal(err)
	}
	var stored []map[string]any
	if err := json.Unmarshal(e.request(t, "tenant-a", "GET", "/records/user_inventory?source="+c.ID, nil, 200), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != len(expected) {
		t.Fatal("duplicate or missing stored records", len(stored))
	}
	byID := map[string]map[string]any{}
	for _, row := range stored {
		id, _ := ocsf.Get(row, "user.uid").(string)
		byID[id] = row
	}
	for _, want := range expected {
		id := want["user.uid"].(string)
		got := byID[id]
		if got == nil {
			t.Fatal("ID lost or rounded", id)
		}
		for field, value := range want {
			if actual := ocsf.Get(got, field); actual != value {
				t.Errorf("%s %s: got %v want %v", id, field, actual, value)
			}
		}
	}
	quarantine, err := e.db.Store.ForTenant("tenant-a").Quarantine(context.Background(), c.ID, 100, 0)
	if err != nil || len(quarantine) != 4 {
		t.Fatal("invalid records not quarantined per run", len(quarantine), err)
	}
	e.request(t, "tenant-b", "GET", "/records/user_inventory?source="+c.ID, nil, 404)
}
