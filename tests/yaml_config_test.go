package tests

import (
	"bytes"
	"configbridge/internal/store"
	"encoding/json"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"testing"
)

func TestYAMLConfigCheckSavePreviewCollectAndIsolation(t *testing.T) {
	e := setup(t)
	c := userConfig("yaml_users", e.vendor.URL+"/users")
	raw, _ := json.Marshal(c)
	var generic any
	json.Unmarshal(raw, &generic)
	body, err := yaml.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	post := func(tenant, path, mime string, body []byte, want int) []byte {
		t.Helper()
		r, _ := http.NewRequest("POST", e.api.URL+path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+key(tenant))
		r.Header.Set("Content-Type", mime)
		response, err := e.api.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		out, _ := io.ReadAll(response.Body)
		if response.StatusCode != want {
			t.Fatalf("%s: %d want %d: %s", path, response.StatusCode, want, out)
		}
		return out
	}
	checked := post("tenant-a", "/configs/check", "text/plain; charset=utf-8", body, 200)
	var normalized struct {
		Config json.RawMessage `json:"config"`
	}
	if json.Unmarshal(checked, &normalized) != nil || !json.Valid(normalized.Config) {
		t.Fatal("no canonical JSON review")
	}
	if string(e.request(t, "tenant-a", "GET", "/configs", nil, 200)) != "[]\n" {
		t.Fatal("check saved config")
	}
	saved := post("tenant-a", "/configs", "application/yaml", body, 201)
	var version struct {
		Revision int    `json:"revision"`
		Hash     string `json:"hash"`
	}
	json.Unmarshal(saved, &version)
	same := post("tenant-a", "/configs", "application/json", normalized.Config, 200)
	var repeated struct {
		Hash      string `json:"hash"`
		Unchanged bool   `json:"unchanged"`
	}
	json.Unmarshal(same, &repeated)
	if !repeated.Unchanged || repeated.Hash != version.Hash {
		t.Fatal("same config created a duplicate revision")
	}
	revision, _ := json.Marshal(map[string]int{"revision": version.Revision})
	e.request(t, "tenant-a", "POST", "/configs/yaml_users/test", revision, 200)
	if string(e.request(t, "tenant-a", "GET", "/records/user_inventory", nil, 200)) != "[]\n" {
		t.Fatal("preview stored rows")
	}
	e.request(t, "tenant-a", "POST", "/configs/yaml_users/activate", revision, 200)
	for i := 0; i < 2; i++ {
		run := e.run(t, "tenant-a", c.ID, 200)
		if run.Accepted != 10 || run.Quarantined != 0 {
			t.Fatal(run)
		}
	}
	var rows []json.RawMessage
	json.Unmarshal(e.request(t, "tenant-a", "GET", "/records/user_inventory?source=yaml_users", nil, 200), &rows)
	if len(rows) != 10 {
		t.Fatal("upsert count", len(rows))
	}
	e.request(t, "tenant-b", "GET", "/configs/yaml_users", nil, 404)
	var report store.AIConsumption
	json.Unmarshal(e.request(t, "tenant-a", "GET", "/ai/usage", nil, 200), &report)
	if report.Requests != 0 {
		t.Fatal("YAML conversion spent AI tokens")
	}
	// Explicit JSON remains strict; YAML must not bypass canonical security rules.
	post("tenant-a", "/configs/check", "application/json", body, 422)
	bad := bytes.Replace(body, []byte("https://"), []byte("http://"), 1)
	post("tenant-a", "/configs/check", "application/yaml", bad, 422)
	post("tenant-a", "/configs/check", "application/yaml", append(body, []byte("\n---\nversion: 1")...), 422)
}
