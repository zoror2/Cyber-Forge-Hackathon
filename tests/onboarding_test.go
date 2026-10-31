package tests

import (
	"configbridge/internal/api"
	"configbridge/internal/onboarding"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func consoleEnv(t *testing.T) (*environment, *onboarding.Console) {
	e := setup(t)
	server := httptest.NewUnstartedServer(nil)
	console, err := onboarding.New("http://" + server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc, UI: console, NotificationTenants: map[string]bool{"tenant-a": true}})
	if err != nil {
		t.Fatal(err)
	}
	e.api.Close()
	server.Config.Handler = h
	server.Start()
	e.api = server
	t.Cleanup(server.Close)
	return e, console
}
func consoleRequest(t *testing.T, e *environment, tenant, method, path string, v url.Values, origin string, want int) (string, http.Header) {
	t.Helper()
	var body io.Reader
	if v != nil {
		body = strings.NewReader(v.Encode())
	}
	req, err := http.NewRequest(method, e.api.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("apikey", key(tenant))
	if v != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := e.api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s %s got %d want %d: %s", method, path, resp.StatusCode, want, string(raw))
	}
	return string(raw), resp.Header
}
func csrf(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(body)
	if len(m) != 2 {
		t.Fatal("CSRF token missing")
	}
	return html.UnescapeString(m[1])
}
func TestOnboardingBrowserFlowGeneratesSavesAndTestsDraft(t *testing.T) {
	e, ui := consoleEnv(t)
	body, headers := consoleRequest(t, e, "tenant-a", "GET", "/onboarding", nil, "", 200)
	if strings.Contains(body, key("tenant-a")) || !strings.Contains(headers.Get("Content-Security-Policy"), "form-action 'self'") || headers.Get("Referrer-Policy") != "same-origin" {
		t.Fatal("unsafe console headers/body")
	}
	consoleRequest(t, e, "tenant-a", "GET", "/onboarding/style.css", nil, "", 200)
	v := url.Values{"csrf_token": {csrf(t, body)}, "entity": {"user"}, "id": {"form_users"}, "name": {"Users from a web form"}, "url": {e.vendor.URL + "/users"}, "port": {strconv.Itoa(portOf(e.vendor.URL))}, "auth_type": {"none"}, "pagination_type": {"page"}, "page_param": {"page"}, "size_param": {"per_page"}, "page_size": {"10"}, "path_id": {"id"}, "transform_id": {"string"}, "path_name": {"profile.name"}}
	generated, _ := consoleRequest(t, e, "tenant-a", "POST", "/onboarding/generate", v, ui.Origin, 200)
	m := regexp.MustCompile(`(?s)<pre id="generated-config">(.*?)</pre>`).FindStringSubmatch(generated)
	if len(m) != 2 {
		t.Fatal("generated config missing")
	}
	raw := html.UnescapeString(m[1])
	c, issues := config.Decode([]byte(raw))
	if len(issues) > 0 || c.ID != "form_users" {
		t.Fatal(issues)
	}
	if _, err := e.db.Store.ForTenant("tenant-a").Config(context.Background(), c.ID, false); err != store.ErrNotFound {
		t.Fatal("generation saved a config")
	}
	action := url.Values{"csrf_token": {csrf(t, generated)}, "config": {raw}}
	downloaded, h := consoleRequest(t, e, "tenant-a", "POST", "/onboarding/download", action, ui.Origin, 200)
	if !strings.Contains(h.Get("Content-Disposition"), "form_users.json") {
		t.Fatal("download header")
	}
	if _, issues = config.Decode([]byte(downloaded)); len(issues) > 0 {
		t.Fatal(issues)
	}
	saved, _ := consoleRequest(t, e, "tenant-a", "POST", "/onboarding/save", action, ui.Origin, 201)
	record, err := e.db.Store.ForTenant("tenant-a").Config(context.Background(), c.ID, false)
	if err != nil || record.Status != "draft" {
		t.Fatal(record, err)
	}
	test := url.Values{"csrf_token": {csrf(t, saved)}, "id": {c.ID}, "revision": {strconv.Itoa(record.Revision)}}
	tested, _ := consoleRequest(t, e, "tenant-a", "POST", "/onboarding/test", test, ui.Origin, 200)
	if !strings.Contains(tested, "Connection test: success") || !strings.Contains(tested, "10</b>") {
		t.Fatal("preview failed")
	}
	e.request(t, "tenant-a", "POST", "/connectors/"+c.ID+"/run", nil, 404)
	rows := e.request(t, "tenant-a", "GET", "/records/users?source="+c.ID, nil, 200)
	if string(rows) != "[]\n" {
		t.Fatal("preview wrote records")
	}
	if string(e.request(t, "tenant-a", "GET", "/runs?connector="+c.ID, nil, 200)) != "[]\n" {
		t.Fatal("preview wrote run history")
	}
	if syncState(t, e, "tenant-a", c.ID).Watermark != nil {
		t.Fatal("preview advanced progress")
	}
}
func TestOnboardingCSRFOriginsTenantIsolationAndValidation(t *testing.T) {
	e, ui := consoleEnv(t)
	a, _ := consoleRequest(t, e, "tenant-a", "GET", "/onboarding", nil, "", 200)
	b, _ := consoleRequest(t, e, "tenant-b", "GET", "/onboarding", nil, "", 200)
	form := url.Values{"csrf_token": {csrf(t, a)}, "entity": {"user"}, "id": {"demo"}, "name": {"Demo"}, "url": {"https://api.example.com"}, "auth_type": {"none"}, "pagination_type": {"none"}, "path_id": {"id"}, "transform_id": {"string"}}
	consoleRequest(t, e, "tenant-a", "POST", "/onboarding/generate", form, "https://evil.example", 403)
	consoleRequest(t, e, "tenant-a", "POST", "/onboarding/generate", form, "", 403)
	consoleRequest(t, e, "tenant-b", "POST", "/onboarding/generate", form, ui.Origin, 403)
	form.Set("csrf_token", "tampered")
	consoleRequest(t, e, "tenant-a", "POST", "/onboarding/generate", form, ui.Origin, 403)
	form.Set("csrf_token", csrf(t, a))
	form.Set("tenant_id", "tenant-b")
	consoleRequest(t, e, "tenant-a", "POST", "/onboarding/generate", form, ui.Origin, 422)
	form.Del("tenant_id")
	form.Add("id", "other")
	consoleRequest(t, e, "tenant-a", "POST", "/onboarding/generate", form, ui.Origin, 400)
	form.Set("id", "demo")
	form.Set("url", "http://example.com")
	consoleRequest(t, e, "tenant-a", "POST", "/onboarding/generate", form, ui.Origin, 422)
	form.Set("url", "https://example.com")
	form.Set("name", `<script>alert(1)</script>`)
	escaped, _ := consoleRequest(t, e, "tenant-a", "POST", "/onboarding/generate", form, ui.Origin, 200)
	if strings.Contains(escaped, "<script>alert") {
		t.Fatal("form output XSS")
	}
	c := userConfig("a_only", e.vendor.URL+"/users")
	e.save(t, "tenant-a", c, false)
	post := url.Values{"csrf_token": {csrf(t, b)}, "id": {"a_only"}, "revision": {"1"}}
	consoleRequest(t, e, "tenant-b", "POST", "/onboarding/test", post, ui.Origin, 404)
	form.Set("notifications_enabled", "on")
	form.Set("csrf_token", csrf(t, b))
	consoleRequest(t, e, "tenant-b", "POST", "/onboarding/generate", form, ui.Origin, 422)
	// Basic API-key authentication is deliberately scoped to the browser console.
	consoleRequest(t, e, "tenant-a", "GET", "/health", nil, "", 401)
	// Existing API routes still refuse browser-origin writes.
	req, _ := http.NewRequest("POST", e.api.URL+"/configs", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+key("tenant-a"))
	req.Header.Set("Origin", ui.Origin)
	resp, err := e.api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("console relaxed REST origin policy")
	}
	// A secret value cannot be pasted as a fabricated reference in the form.
	form.Set("csrf_token", csrf(t, a))
	form.Del("notifications_enabled")
	form.Set("auth_type", "bearer")
	form.Set("secret_name", "PRIVATE_SENTINEL")
	rejected, _ := consoleRequest(t, e, "tenant-a", "POST", "/onboarding/generate", form, ui.Origin, 422)
	if strings.Contains(rejected, "PRIVATE_SENTINEL") {
		t.Fatal("secret reference was echoed")
	}
	// Form token/config are never API keys or model inputs.
	var alerts []store.Alert
	json.Unmarshal(e.request(t, "tenant-a", "GET", "/alerts", nil, 200), &alerts)
	if len(alerts) != 0 {
		t.Fatal("form generated alerts")
	}
}
