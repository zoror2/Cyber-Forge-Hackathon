package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMount(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	h := Mount(api)
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	if w := get("/ui/"); w.Code != 200 || !strings.Contains(w.Body.String(), "app.js") ||
		!strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatal("console not served with CSP", w.Code)
	}
	for _, f := range []string{"/ui/app.js", "/ui/app.css"} {
		if w := get(f); w.Code != 200 {
			t.Fatal(f, w.Code)
		}
	}
	var meta struct {
		Schema struct {
			Version string         `json:"version"`
			Classes map[string]any `json:"classes"`
		} `json:"schema"`
		Identity map[string]string `json:"identity"`
	}
	if w := get("/ui/ocsf.json"); w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &meta) != nil ||
		meta.Schema.Version == "" || len(meta.Schema.Classes) < 5 || meta.Identity["user_inventory"] != "user.uid" {
		t.Fatal("ocsf metadata", w.Code)
	}
	if w := get("/"); w.Code != 302 || w.Header().Get("Location") != "/ui/" {
		t.Fatal("root redirect", w.Code)
	}
	// data routes still go to the authenticated API
	for _, p := range []string{"/health", "/records/user_inventory", "/ui-not-really"} {
		if w := get(p); w.Code != 401 {
			t.Fatal(p, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/ui/", nil))
	if w.Code == 200 {
		t.Fatal("POST to static console accepted")
	}
}
