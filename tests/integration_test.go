// These tests run Member A's real TLS HTTP client, mapper, API and PostgreSQL
// together. Sources are deterministic local fixtures, never live vendors.
package tests

import (
	"bytes"
	"configbridge/internal/api"
	"configbridge/internal/egress"
	"configbridge/internal/engine"
	"configbridge/internal/mockvendor"
	"configbridge/internal/runner"
	"configbridge/internal/store"
	"configbridge/internal/testutil"
	"configbridge/pkg/config"
	"configbridge/pkg/model"
	"configbridge/pkg/secrets"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type environment struct {
	db          *testutil.DB
	vendor, api *httptest.Server
	requests    *engine.Engine
	runs        *runner.Runner
	svc         *secrets.Service
	logs        *safeLog
	calls       sync.Map
}
type safeLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *safeLog) Write(b []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(b) }
func (l *safeLog) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }
func key(tenant string) string                 { return strings.Repeat(tenant+"-key-", 4) }
func setup(t *testing.T) *environment {
	t.Helper()
	db := testutil.Setup(t)
	e := &environment{db: db, logs: &safeLog{}}
	mux := http.NewServeMux()
	mux.Handle("/", mockvendor.Handler())
	mux.HandleFunc("GET /fixture-events", func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile("../pkg/mapping/testdata/events.json")
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})
	mux.HandleFunc("GET /clean", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"id":1,"profile":{"name":"Demo"},"last_login":"2026-10-31T15:30:00+05:30"}]`)
	})
	mux.HandleFunc("GET /devices", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"id":"device-1","hostname":"synthetic-host","last_seen":"2026-10-31T10:00:00Z"}]`)
	})
	mux.HandleFunc("GET /api-key", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "SYNTHETIC_SENTINEL" {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, `[{"id":1}]`)
	})
	mux.HandleFunc("GET /basic", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "demo" || p != "SYNTHETIC_SENTINEL" {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, `[{"id":1}]`)
	})
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "client" || p != "SYNTHETIC_SENTINEL" {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, `{"access_token":"mock-token","token_type":"Bearer","expires_in":3600}`)
	})
	mux.HandleFunc("GET /invalid", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `not-json`) })
	mux.HandleFunc("GET /trailing", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `[{"id":1}] trailing-garbage`) })
	mux.HandleFunc("POST /oauth/bad", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"access_token":"mock-token","token_type":"SYNTHETIC_SENTINEL","expires_in":3600}`)
	})
	mux.HandleFunc("GET /cut", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<https://%s/cut?page=2>; rel="next"`, r.Host))
		io.WriteString(w, `[{"id":1}]`)
	})
	e.vendor = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter, _ := e.calls.LoadOrStore(r.URL.Path, &atomic.Int32{})
		counter.(*atomic.Int32).Add(1)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(e.vendor.Close)
	root := e.vendor.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	local, err := secrets.NewLocal(db.Store, map[string]string{"tenant-a": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), "tenant-b": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = &secrets.Service{Store: db.Store, Backend: local, BackendName: "local"}
	e.requests = engine.New(e.svc, egress.Policy{RootCAs: root, AllowPrivate: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}, slog.New(slog.NewTextHandler(e.logs, nil)))
	e.runs = runner.New(db.Store, e.requests)
	h, err := api.New(&api.API{Store: db.Store, Engine: e.runs, Secrets: e.svc})
	if err != nil {
		t.Fatal(err)
	}
	e.api = httptest.NewServer(h)
	t.Cleanup(e.api.Close)
	return e
}
func (e *environment) request(t *testing.T, tenant, method, path string, body []byte, want int) []byte {
	t.Helper()
	req, err := http.NewRequest(method, e.api.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+key(tenant))
	req.Header.Set("X-Tenant-ID", "tenant-b") // ignored: identity only comes from the key
	resp, err := e.api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s %s got %d want %d: %s", method, path, resp.StatusCode, want, b)
	}
	return b
}
func userConfig(id, url string) config.Config {
	path := func(s string) *string { return &s }
	c := config.Config{Version: 1, ID: id, Name: id, Request: engine.Request{URL: url, Method: "GET", TimeoutSeconds: 1}, Auth: engine.Auth{Type: "none"}, Pagination: engine.Pagination{Type: "none"}, Destination: config.Destination{Entity: "user", Mapping: map[string]config.Field{"id": {Path: path("id"), Required: true, Transform: "string"}, "name": {Path: path("profile.name")}, "email": {Path: path("email")}, "last_login": {Path: path("last_login"), Transform: "datetime"}}}, Retry: engine.Retry{MaxAttempts: 2, BaseDelayMillis: 1, MaxRetryAfterSeconds: 5}}
	c.Defaults()
	c.Limits.MaxRunSeconds = 10
	c.Limits.MaxPages = 10
	return c
}
func (e *environment) save(t *testing.T, tenant string, c config.Config, live bool) int {
	t.Helper()
	raw, _ := json.Marshal(c)
	b := e.request(t, tenant, "POST", "/configs", raw, 201)
	var saved struct {
		Revision int `json:"revision"`
	}
	json.Unmarshal(b, &saved)
	e.request(t, tenant, "POST", "/configs/"+c.ID+"/validate", nil, 200)
	if live {
		e.request(t, tenant, "POST", "/configs/"+c.ID+"/activate", []byte(fmt.Sprintf(`{"revision":%d}`, saved.Revision)), 200)
	}
	return saved.Revision
}
func (e *environment) run(t *testing.T, tenant, id string, status int) model.Run {
	t.Helper()
	b := e.request(t, tenant, "POST", "/connectors/"+id+"/run", nil, status)
	var r model.Run
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCombinedAPIPageMappingAndIsolation(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	a := e.db.Store.ForTenant("tenant-a")
	b := e.db.Store.ForTenant("tenant-b")
	c := userConfig("users", e.vendor.URL+"/users")
	c.Pagination = engine.Pagination{Type: "page", PageParam: "page", SizeParam: "per_page", PageSize: 10}
	c.Name = "<script>untrusted</script>"
	e.save(t, "tenant-a", c, false)
	e.request(t, "tenant-a", "POST", "/connectors/users/run", nil, 404)
	e.request(t, "tenant-a", "POST", "/configs/users/activate", []byte(`{"revision":1}`), 200)
	e.request(t, "tenant-a", "POST", "/connectors/users/run", []byte(`{}`), 400)
	e.request(t, "tenant-a", "POST", "/connectors/users/test", nil, 200)
	runs, _ := a.Runs(ctx, "", 100, 0)
	rows, _ := a.Records(ctx, "user", "", 100, 0)
	if len(runs) != 0 || len(rows) != 0 {
		t.Fatal("test connection wrote data")
	}
	for i := 0; i < 2; i++ {
		r := e.run(t, "tenant-a", "users", 200)
		if r.Pages != 3 || r.Accepted != 25 || r.Quarantined != 0 || r.Outcome != "success" || r.TenantID != "tenant-a" {
			t.Fatal(r)
		}
	}
	rows, err := a.Records(ctx, "user", "users", 100, 0)
	if err != nil || len(rows) != 25 {
		t.Fatal("duplicates or missing rows", len(rows), err)
	}
	var first map[string]any
	json.Unmarshal(rows[0], &first)
	if first["source"] != "users" || first["tenant_id"] != "tenant-a" || first["fetched_at"] == nil {
		t.Fatal("missing provenance")
	}
	for _, path := range []string{"/configs/users/validate", "/configs/users/activate", "/connectors/users/test", "/connectors/users/run"} {
		var body []byte
		if strings.HasSuffix(path, "activate") {
			body = []byte(`{"revision":1}`)
		}
		e.request(t, "tenant-b", "POST", path, body, 404)
	}
	for _, path := range []string{"/runs?connector=users", "/records/users?source=users", "/records/devices?source=users", "/records/events?source=users", "/quarantine?connector=users"} {
		e.request(t, "tenant-b", "GET", path, nil, 404)
	}
	for _, path := range []string{"/health", "/runs", "/records/users", "/records/devices", "/records/events", "/quarantine", "/secrets"} {
		raw := e.request(t, "tenant-b", "GET", path, nil, 200)
		if strings.TrimSpace(string(raw)) != "[]" {
			t.Fatalf("tenant B saw data through %s", path)
		}
	}
	e.save(t, "tenant-b", c, true)
	e.run(t, "tenant-b", "users", 200)
	other, _ := b.Records(ctx, "user", "", 100, 0)
	if len(other) != 25 {
		t.Fatal("tenant B couldn't use same IDs")
	}
	for _, raw := range other {
		if !bytes.Contains(raw, []byte(`"tenant_id": "tenant-b"`)) && !bytes.Contains(raw, []byte(`"tenant_id":"tenant-b"`)) {
			t.Fatal("tenant crossed storage")
		}
	}
	htmlReq, _ := http.NewRequest("GET", e.api.URL+"/health", nil)
	htmlReq.Header.Set("Authorization", "Bearer "+key("tenant-a"))
	htmlReq.Header.Set("Accept", "text/html")
	resp, err := e.api.Client().Do(htmlReq)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(html, []byte("<script>")) || !bytes.Contains(html, []byte("&lt;script&gt;")) {
		t.Fatal("HTML escaping failed")
	}
	c.Name = "draft v2"
	revision := e.save(t, "tenant-a", c, false)
	saved, _ := a.Config(ctx, c.ID, true)
	if saved.Revision != 1 {
		t.Fatal("draft replaced live")
	}
	e.request(t, "tenant-a", "POST", "/configs/users/activate", []byte(fmt.Sprintf(`{"revision":%d}`, revision)), 200)
	e.request(t, "tenant-a", "GET", "/runs?limit=501", nil, 400)
	raw, _ := json.Marshal(c)
	raw = bytes.Replace(raw, []byte(`"version":1`), []byte(`"tenant_id":"tenant-b","version":1`), 1)
	e.request(t, "tenant-a", "POST", "/configs", raw, 422)
	e.request(t, "tenant-a", "POST", "/configs", bytes.Repeat([]byte("x"), config.MaxBytes+1), 413)
	e.request(t, "tenant-a", "PUT", "/secrets/duplicate", []byte(`{"value":"a","value":"b","allowed_host":"api.example.com"}`), 400)
	if _, err = e.db.Admin.Exec(ctx, "UPDATE "+e.db.Schema+".api_keys SET active=false WHERE tenant_id='tenant-a'"); err != nil {
		t.Fatal(err)
	}
	e.request(t, "tenant-a", "GET", "/health", nil, 401)
}

func TestCombinedQuarantineDatesAndUpsert(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	raw, err := os.ReadFile("../configs/fixture_events.json")
	if err != nil {
		t.Fatal(err)
	}
	c, issues := config.Decode(raw)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	c.Request.URL = e.vendor.URL + "/fixture-events"
	e.save(t, "tenant-a", c, true)
	for i := 0; i < 2; i++ {
		r := e.run(t, "tenant-a", c.ID, 200)
		if r.Accepted != 3 || r.Quarantined != 1 || r.Outcome != "completed_with_errors" {
			t.Fatal(r)
		}
	}
	scope := e.db.Store.ForTenant("tenant-a")
	rows, _ := scope.Records(ctx, "event", c.ID, 100, 0)
	q, _ := scope.Quarantine(ctx, c.ID, 100, 0)
	if len(rows) != 3 || len(q) != 2 || q[0]["field"] != "id" || q[0]["page"] != 1 {
		t.Fatal("quarantine or upsert mismatch")
	}
	if !bytes.Contains(rows[0], []byte("timestamp_precision")) {
		t.Fatal("date precision lost")
	}
	c2 := userConfig("bad-users", e.vendor.URL+"/malformed")
	e.save(t, "tenant-a", c2, true)
	r := e.run(t, "tenant-a", c2.ID, 200)
	if r.Accepted != 2 || r.Quarantined != 2 {
		t.Fatal("missing ID/date not quarantined or optional null rejected", r)
	}
	health, _ := scope.Health(ctx, 100, 0)
	for _, h := range health {
		if h.Status != "degraded" || h.LastSuccess != nil {
			t.Fatal("bad rows reported healthy")
		}
	}
	c2.ID = "exact-number"
	c2.Request.URL = e.vendor.URL + "/clean"
	e.save(t, "tenant-a", c2, true)
	r = e.run(t, "tenant-a", c2.ID, 200)
	if r.Accepted != 1 {
		t.Fatal(r)
	}
}

func TestCombinedOffsetEventsAndDevices(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	path := func(s string) *string { return &s }
	c := userConfig("issues", e.vendor.URL+"/issues")
	c.ItemsPath = "issues"
	c.Pagination = engine.Pagination{Type: "offset", OffsetParam: "startAt", SizeParam: "maxResults", PageSize: 10}
	c.Destination = config.Destination{Entity: "event", Mapping: map[string]config.Field{
		"id": {Path: path("key"), Required: true, Transform: "string"}, "type": {Constant: "repository_issue"}, "description": {Path: path("fields.summary"), Required: true},
		"severity":  {Path: path("fields.priority.name"), Transform: "lookup", Lookup: map[string]string{"High": "high"}},
		"timestamp": {Path: path("fields.created"), Required: true, Transform: "datetime", Format: "2006-01-02T15:04:05.000-0700"},
	}}
	e.save(t, "tenant-a", c, true)
	for i := 0; i < 2; i++ {
		r := e.run(t, "tenant-a", c.ID, 200)
		if r.Pages != 3 || r.Accepted != 25 || r.Quarantined != 0 {
			t.Fatal(r)
		}
	}
	scope := e.db.Store.ForTenant("tenant-a")
	events, err := scope.Records(ctx, "event", c.ID, 100, 0)
	if err != nil || len(events) != 25 {
		t.Fatal("offset upsert failed", err)
	}
	var event map[string]any
	json.Unmarshal(events[0], &event)
	if event["timestamp"] != "2026-10-20T10:00:00Z" || event["severity"] != "high" {
		t.Fatal("non-ISO date/lookup mapping failed", event)
	}
	d := userConfig("devices", e.vendor.URL+"/devices")
	d.Destination = config.Destination{Entity: "device", Mapping: map[string]config.Field{"id": {Path: path("id"), Required: true}, "hostname": {Path: path("hostname")}, "last_seen": {Path: path("last_seen"), Transform: "datetime"}}}
	e.save(t, "tenant-a", d, true)
	for i := 0; i < 2; i++ {
		r := e.run(t, "tenant-a", d.ID, 200)
		if r.Accepted != 1 {
			t.Fatal(r)
		}
	}
	devices, err := scope.Records(ctx, "device", d.ID, 100, 0)
	if err != nil || len(devices) != 1 {
		t.Fatal("device persistence failed", err)
	}
	var device map[string]any
	json.Unmarshal(devices[0], &device)
	if device["hostname"] != "synthetic-host" || device["owner"] != nil || device["last_seen"] != "2026-10-31T10:00:00Z" {
		t.Fatal("device schema mismatch")
	}
}

func TestCombinedSecretsAndAuthentication(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	host, _ := url.Parse(e.vendor.URL)
	put := func(tenant, value string) {
		body, _ := json.Marshal(map[string]string{"value": value, "allowed_host": host.Host})
		if b := e.request(t, tenant, "PUT", "/secrets/shared", body, 204); len(b) != 0 {
			t.Fatal("secret echoed")
		}
	}
	put("tenant-a", "mock-token")
	put("tenant-b", "wrong-for-b")
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		c := userConfig("secure", e.vendor.URL+"/secure")
		c.Auth = engine.Auth{Type: "bearer", Secret: "shared"}
		e.save(t, tenant, c, true)
	}
	if r := e.run(t, "tenant-a", "secure", 200); r.Accepted != 3 {
		t.Fatal(r)
	}
	if r := e.run(t, "tenant-b", "secure", 502); r.Error != "auth_failed" {
		t.Fatal(r)
	}
	before := e.callsCount("/secure")
	e.run(t, "tenant-b", "secure", 502)
	if e.callsCount("/secure") != before+1 {
		t.Fatal("401 retry storm")
	}
	if _, err := e.svc.Get(ctx, "tenant-b", "missing"); err == nil {
		t.Fatal("missing secret accepted")
	}
	body, _ := json.Marshal(map[string]string{"value": "not-echoed", "allowed_host": "other.example.com"})
	e.request(t, "tenant-a", "PUT", "/secrets/shared", body, 409)
	put("tenant-b", "mock-token")
	e.run(t, "tenant-b", "secure", 200)
	for _, kind := range []string{"api_key", "basic", "oauth2_client_credentials"} {
		put("tenant-a", "SYNTHETIC_SENTINEL")
		c := userConfig(kind, e.vendor.URL+"/api-key")
		c.Auth = engine.Auth{Type: kind, Secret: "shared", Header: "X-API-Key", Username: "demo", ClientID: "client", TokenURL: e.vendor.URL + "/oauth/token"}
		if kind == "basic" {
			c.Request.URL = e.vendor.URL + "/basic"
		}
		if kind == "oauth2_client_credentials" {
			c.Request.URL = e.vendor.URL + "/secure"
		}
		e.save(t, "tenant-a", c, true)
		e.run(t, "tenant-a", kind, 200)
	}
	badOAuth := userConfig("bad-oauth", e.vendor.URL+"/secure")
	badOAuth.Auth = engine.Auth{Type: "oauth2_client_credentials", Secret: "shared", ClientID: "client", TokenURL: e.vendor.URL + "/oauth/bad"}
	e.save(t, "tenant-a", badOAuth, true)
	e.run(t, "tenant-a", badOAuth.ID, 502)
	blocked := userConfig("wrong-host", e.vendor.URL+"/secure")
	blocked.Auth = engine.Auth{Type: "bearer", Secret: "wrong-host"}
	body, _ = json.Marshal(map[string]string{"value": "SYNTHETIC_SENTINEL", "allowed_host": "other.example.com"})
	e.request(t, "tenant-a", "PUT", "/secrets/wrong-host", body, 204)
	e.save(t, "tenant-a", blocked, true)
	before = e.callsCount("/secure")
	if r := e.run(t, "tenant-a", blocked.ID, 502); r.Error != "destination_denied" {
		t.Fatal(r)
	}
	if e.callsCount("/secure") != before {
		t.Fatal("bound secret sent to wrong host")
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		for _, path := range []string{"/secrets", "/runs", "/quarantine"} {
			raw := e.request(t, tenant, "GET", path, nil, 200)
			if bytes.Contains(raw, []byte("SYNTHETIC_SENTINEL")) || bytes.Contains(raw, []byte("mock-token")) {
				t.Fatal("secret leaked through API")
			}
		}
	}
	if strings.Contains(e.logs.String(), "SYNTHETIC_SENTINEL") || strings.Contains(e.logs.String(), "mock-token") {
		t.Fatal("secret leaked into engine logs")
	}
	// Only ciphertext is persisted, and RLS still scopes this direct query.
	err := e.db.Store.ForTenant("tenant-a").WithTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT ciphertext FROM credentials_values")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b []byte
			if err = rows.Scan(&b); err != nil {
				return err
			}
			if bytes.Contains(b, []byte("SYNTHETIC_SENTINEL")) {
				t.Fatal("plaintext secret in PostgreSQL")
			}
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
}
func (e *environment) callsCount(path string) int32 {
	v, ok := e.calls.Load(path)
	if !ok {
		return 0
	}
	return v.(*atomic.Int32).Load()
}

func TestCombinedFailureRecovery(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	cases := []struct {
		id, path string
		params   map[string]string
		want     string
		partial  bool
	}{
		{"retry-success", "/flaky", map[string]string{"scenario_id": "retry-success", "fail": "2", "code": "500"}, "", false},
		{"retry-exhausted", "/flaky", map[string]string{"scenario_id": "retry-exhausted", "fail": "10", "code": "500"}, "vendor_http_failed", false},
		{"rate-limit", "/ratelimit", map[string]string{"scenario_id": "rate-one", "retry_after": "1"}, "", false},
		{"rate-budget", "/ratelimit", map[string]string{"scenario_id": "rate-budget", "retry_after": "60"}, "rate_limited", false},
		{"timeout", "/hang", map[string]string{"seconds": "2"}, "timeout", false},
		{"redirect", "/redirect", nil, "destination_denied", false},
		{"huge", "/huge", map[string]string{"mb": "1"}, "response_too_large", false},
		{"invalid", "/invalid", nil, "collection_failed", false},
		{"trailing", "/trailing", nil, "collection_failed", false},
		{"offhost", "/offhost", nil, "destination_denied", true},
		{"cut", "/cut", nil, "collection_failed", true},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			c := userConfig(tc.id, e.vendor.URL+tc.path)
			c.Request.Params = tc.params
			c.Retry.MaxAttempts = 3
			if tc.id == "offhost" || tc.id == "cut" {
				c.Pagination.Type = "link"
			}
			if tc.id == "huge" {
				c.Limits.MaxResponseBytes = 1000
			}
			e.save(t, "tenant-a", c, true)
			start := time.Now()
			status := 200
			if tc.want != "" {
				status = 502
			}
			r := e.run(t, "tenant-a", c.ID, status)
			if tc.id == "retry-success" && r.Attempts != 3 {
				t.Fatal("retry attempts not counted", r.Attempts)
			}
			if r.Error != tc.want {
				t.Fatalf("want %s got %s", tc.want, r.Error)
			}
			if tc.id == "rate-limit" && time.Since(start) < time.Second {
				t.Fatal("retried before Retry-After")
			}
			if tc.want == "" && r.Accepted != 3 {
				t.Fatal(r)
			}
			if tc.partial && r.Outcome != "incomplete" {
				t.Fatal("partial run reported complete", r)
			}
			if tc.want != "" && !tc.partial && r.Outcome != "failed" {
				t.Fatal(r)
			}
			if tc.want != "" {
				runs, _ := e.db.Store.ForTenant("tenant-a").Runs(ctx, c.ID, 100, 0)
				if len(runs) != 1 || runs[0].Error != tc.want {
					t.Fatal("failure not persisted")
				}
			}
		})
	}
	for _, id := range []string{"offhost", "cut"} {
		rows, _ := e.db.Store.ForTenant("tenant-a").Records(ctx, "user", id, 100, 0)
		if len(rows) == 0 {
			t.Fatal("earlier committed page lost")
		}
	}
	c := userConfig("record-limit", e.vendor.URL+"/users")
	c.Limits.MaxRecords = 2
	e.save(t, "tenant-a", c, true)
	if r := e.run(t, "tenant-a", c.ID, 502); r.Outcome != "incomplete" {
		t.Fatal(r)
	}
	c = userConfig("page-limit", e.vendor.URL+"/users")
	c.Pagination = engine.Pagination{Type: "page", PageParam: "page", SizeParam: "per_page", PageSize: 10}
	c.Limits.MaxPages = 1
	e.save(t, "tenant-a", c, true)
	if r := e.run(t, "tenant-a", c.ID, 502); r.Outcome != "incomplete" || r.Accepted != 10 {
		t.Fatal(r)
	}
	private := userConfig("private", "https://169.254.169.254/latest/meta-data/")
	e.save(t, "tenant-a", private, true)
	if r := e.run(t, "tenant-a", private.ID, 502); r.Error != "destination_denied" {
		t.Fatal("metadata destination allowed", r)
	}
}

func TestSchedulerLocksRecoveryAndTenantFairness(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		c := userConfig("scheduled", e.vendor.URL+"/clean")
		c.Schedule = config.Schedule{Enabled: true, IntervalSeconds: 1}
		e.save(t, tenant, c, true)
	}
	a := e.db.Store.ForTenant("tenant-a")
	b := e.db.Store.ForTenant("tenant-b")
	_, release, err := a.Lock(ctx, "scheduled")
	if err != nil {
		t.Fatal(err)
	}
	_, releaseB, err := b.Lock(ctx, "scheduled")
	if err != nil {
		release()
		t.Fatal("tenant A lock blocked B", err)
	}
	releaseB()
	if _, _, err = a.Lock(ctx, "scheduled"); err != store.ErrBusy {
		release()
		t.Fatal("same tenant connector lock did not conflict")
	}
	if err = a.Activate(ctx, "scheduled", 1); err != store.ErrBusy {
		release()
		t.Fatal("activation during run allowed")
	}
	scheduleCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { e.runs.Schedule(scheduleCtx, 20*time.Millisecond); close(done) }()
	waitRuns := func(scope store.Scope, n int) bool {
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			runs, err := scope.Runs(ctx, "scheduled", 100, 0)
			if err != nil {
				t.Fatal(err)
			}
			success := 0
			for _, r := range runs {
				if r.Outcome == "success" {
					success++
				}
			}
			if success >= n {
				return true
			}
			time.Sleep(50 * time.Millisecond)
		}
		return false
	}
	if !waitRuns(b, 1) {
		release()
		cancel()
		<-done
		t.Fatal("blocked tenant A starved tenant B")
	}
	release()
	if !waitRuns(a, 2) || !waitRuns(b, 2) {
		cancel()
		<-done
		t.Fatal("scheduler did not finish two runs per tenant")
	}
	cancel()
	<-done
	saved, err := a.Config(ctx, "scheduled", true)
	if err != nil {
		t.Fatal(err)
	}
	cfg := saved.Config
	cfg.Schedule.Enabled = false
	e.save(t, "tenant-a", cfg, true)
	jobs, err := e.db.Store.Jobs(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range jobs {
		if j.Tenant == "tenant-a" {
			t.Fatal("disabled schedule still due")
		}
	}
	_, release, err = a.Lock(ctx, "scheduled")
	if err != nil {
		t.Fatal(err)
	}
	current, err := a.Config(ctx, "scheduled", true)
	if err != nil {
		release()
		t.Fatal(err)
	}
	r := model.Run{TenantID: "tenant-a", ID: "abandoned", Connector: "scheduled", ConfigVersion: current.Revision, ConfigHash: current.Hash, Mode: "live", StartedAt: time.Now().UTC()}
	if err = a.StartRun(ctx, r); err != nil {
		release()
		t.Fatal(err)
	}
	if err = e.db.Store.Recover(ctx); err != nil {
		release()
		t.Fatal(err)
	}
	runs, _ := a.Runs(ctx, "scheduled", 100, 0)
	if runs[0].Outcome != "running" {
		release()
		t.Fatal("active worker interrupted")
	}
	release()
	if err = e.db.Store.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	runs, _ = a.Runs(ctx, "scheduled", 100, 0)
	if runs[0].Outcome != "interrupted" {
		t.Fatal("abandoned run not recovered")
	}
	if err = a.SavePage(ctx, r.ID, r.Connector, nil, nil); err == nil {
		t.Fatal("abandoned writer was not fenced")
	}
	now := time.Now().UTC()
	r.EndedAt = &now
	r.Outcome = "success"
	if err = a.FinishRun(ctx, r, 60); err == nil {
		t.Fatal("abandoned run changed sync state")
	}
}
