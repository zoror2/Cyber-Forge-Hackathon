package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zoror2/Cyber-Forge-Hackathon/internal/api"
	"github.com/zoror2/Cyber-Forge-Hackathon/internal/engine"
	"github.com/zoror2/Cyber-Forge-Hackathon/internal/fixture"
	"github.com/zoror2/Cyber-Forge-Hackathon/internal/store"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/collector"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/config"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/model"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/secrets"
)

type fetchFunc func(context.Context, config.Config, func(collector.Page) error) error

func (f fetchFunc) Fetch(c context.Context, cfg config.Config, emit func(collector.Page) error) error {
	return f(c, cfg, emit)
}
func setup(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run real PostgreSQL integration tests")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 8)
	rand.Read(b)
	schema := "test_" + hex.EncodeToString(b)
	if _, err = admin.Pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Pool.Close()
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	s, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Pool.Close()
		admin.Pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Pool.Close()
	})
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal("migration not repeatable", err)
	}
	return s
}
func fixtureConfig(t *testing.T) config.Config {
	t.Helper()
	b, e := os.ReadFile("../configs/fixture_events.yaml")
	if e != nil {
		t.Fatal(e)
	}
	c, issues := config.Decode(b)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	return c
}
func activate(t *testing.T, s *store.Store, c config.Config) {
	t.Helper()
	saved, e := s.SaveConfig(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Activate(context.Background(), c.ID, saved.Revision); e != nil {
		t.Fatal(e)
	}
}
func TestAPICompleteFixtureFlow(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	local, e := secrets.NewLocal(s.Pool, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	if e != nil {
		t.Fatal(e)
	}
	svc := &secrets.Service{Pool: s.Pool, Backend: local, BackendName: "local"}
	eng := engine.New(s, fixture.Fetcher{}, "fixture")
	token := strings.Repeat("unit-test-token-", 3)
	handler, e := api.New(&api.API{Store: s, Engine: eng, Secrets: svc}, token)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	request := func(method, path string, body []byte, want int) []byte {
		t.Helper()
		req, e := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s got %d wanted %d: %s", method, path, resp.StatusCode, want, b)
		}
		return b
	}
	cfg := fixtureConfig(t)
	cfg.Name = "<script>alert(1)</script>"
	b, _ := json.Marshal(cfg)
	request("POST", "/configs", b, 201)
	request("POST", "/configs/fixture_events/validate", nil, 200)
	request("POST", "/connectors/fixture_events/run", nil, 404)
	request("POST", "/configs/fixture_events/activate", []byte(`{"revision":1}`), 200)
	request("POST", "/connectors/fixture_events/run", []byte(`{}`), 400)
	// Test connection checks a sample without touching production data or run history.
	request("POST", "/connectors/fixture_events/test", nil, 200)
	runs, _ := s.Runs(ctx, "", 100, 0)
	rows, _ := s.Records(ctx, "event", "", 100, 0)
	if len(runs) != 0 || len(rows) != 0 {
		t.Fatal("test connection wrote data")
	}
	for i := 0; i < 2; i++ {
		body := request("POST", "/connectors/fixture_events/run", nil, 200)
		var r model.Run
		json.Unmarshal(body, &r)
		if r.Received != 4 || r.Accepted != 3 || r.Quarantined != 1 || r.Outcome != "completed_with_errors" || r.Mode != "fixture" {
			t.Fatal(r)
		}
	}
	records := request("GET", "/records/events", nil, 200)
	var saved []json.RawMessage
	json.Unmarshal(records, &saved)
	if len(saved) != 3 {
		t.Fatalf("duplicate records: %d", len(saved))
	}
	bad := request("GET", "/quarantine?connector=fixture_events", nil, 200)
	if !bytes.Contains(bad, []byte("required value is missing")) {
		t.Fatal("no actionable quarantine")
	}
	request("GET", "/runs?connector=fixture_events&limit=1", nil, 200)
	request("GET", "/records/events?limit=501", nil, 400)
	health := request("GET", "/health", nil, 200)
	if !bytes.Contains(health, []byte("degraded")) {
		t.Fatal("quarantine shown as healthy")
	}
	req, _ := http.NewRequest("GET", server.URL+"/health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "text/html")
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	html, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(html, []byte("<script>")) || !bytes.Contains(html, []byte("&lt;script&gt;")) {
		t.Fatal("unescaped HTML")
	}
	sentinel := "UNIQUE_SENTINEL_VENDOR_VALUE"
	secretBody, _ := json.Marshal(map[string]string{"value": sentinel, "allowed_host": "api.example.com"})
	if b := request("PUT", "/secrets/vendor", secretBody, 204); len(b) != 0 {
		t.Fatal("secret echoed")
	}
	listed := request("GET", "/secrets", nil, 200)
	if bytes.Contains(listed, []byte(sentinel)) || bytes.Contains(listed, []byte(`"value"`)) {
		t.Fatal("secret list leaked")
	}
	got, e := svc.GetSecret(ctx, "vendor")
	if e != nil || got.Value != sentinel || got.AllowedHost != "api.example.com" {
		t.Fatal("secret interface failed")
	}
	var ciphertext []byte
	if e = s.Pool.QueryRow(ctx, "SELECT ciphertext FROM credentials_values WHERE name='vendor'").Scan(&ciphertext); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(ciphertext, []byte(sentinel)) {
		t.Fatal("plaintext database secret")
	}
	secretBody, _ = json.Marshal(map[string]string{"value": "rotation", "allowed_host": "api.example.com"})
	request("PUT", "/secrets/vendor", secretBody, 204)
	secretBody, _ = json.Marshal(map[string]string{"value": sentinel, "allowed_host": "other.example.com"})
	request("PUT", "/secrets/vendor", secretBody, 409)
	// A newly submitted version stays draft; previous live revision still runs.
	cfg.Name = "v2"
	b, _ = json.Marshal(cfg)
	request("POST", "/configs", b, 201)
	current, e := s.Config(ctx, cfg.ID, true)
	if e != nil || current.Revision != 1 {
		t.Fatal("draft replaced live config")
	}
	request("POST", "/configs/fixture_events/activate", []byte(`{"revision":2}`), 200)
	current, e = s.Config(ctx, cfg.ID, true)
	if e != nil || current.Revision != 2 {
		t.Fatal("activation failed")
	}
	// Same external IDs belonging to another source remain separate.
	cfg.ID = "second_source"
	activate(t, s, cfg)
	if _, e = eng.Run(ctx, cfg.ID, false, false); e != nil {
		t.Fatal(e)
	}
	rows, _ = s.Records(ctx, "event", "", 100, 0)
	if len(rows) != 6 {
		t.Fatal("source collision", len(rows))
	}
}
func TestLocksPartialFailureAndLimits(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	cfg := fixtureConfig(t)
	activate(t, s, cfg)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	slow := fetchFunc(func(ctx context.Context, c config.Config, emit func(collector.Page) error) error {
		close(entered)
		select {
		case <-release:
			return fixture.Fetcher{}.Fetch(ctx, c, emit)
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	a := engine.New(s, slow, "fixture")
	b := engine.New(s, fixture.Fetcher{}, "fixture")
	go func() { _, e := a.Run(ctx, cfg.ID, false, false); done <- e }()
	<-entered
	if _, e := b.Run(ctx, cfg.ID, false, false); !errors.Is(e, store.ErrBusy) {
		t.Fatal("overlapping run allowed", e)
	}
	if e := s.Activate(ctx, cfg.ID, 1); !errors.Is(e, store.ErrBusy) {
		t.Fatal("activation during run allowed", e)
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	failure := fetchFunc(func(ctx context.Context, c config.Config, emit func(collector.Page) error) error {
		if e := (fixture.Fetcher{}).Fetch(ctx, c, emit); e != nil {
			return e
		}
		return errors.New("SENTINEL_SECRET_IN_RAW_ERROR https://private.invalid")
	})
	failed := engine.New(s, failure, "fixture")
	r, e := failed.Run(ctx, cfg.ID, false, false)
	if e == nil || r.Outcome != "incomplete" || r.Error != "collection_failed" {
		t.Fatal(r, e)
	}
	runs, _ := s.Runs(ctx, cfg.ID, 100, 0)
	raw, _ := json.Marshal(runs)
	if bytes.Contains(raw, []byte("SENTINEL")) {
		t.Fatal("error leaked into run history")
	}
	cfg.ID = "limited"
	cfg.Limits.MaxRecords = 2
	activate(t, s, cfg)
	r, e = b.Run(ctx, cfg.ID, false, false)
	if e == nil || r.Outcome != "incomplete" {
		t.Fatal("limit reported success")
	}
	records, _ := s.Records(ctx, "event", "limited", 100, 0)
	if len(records) != 0 {
		t.Fatal("oversized page partly written")
	}
	cfg.ID = "unconnected"
	activate(t, s, cfg)
	r, e = engine.New(s, collector.Unavailable{}, "live").Run(ctx, cfg.ID, false, false)
	if !errors.Is(e, collector.ErrUnavailable) || r.Outcome != "failed" {
		t.Fatal("unconnected engine reported success")
	}
}
func TestSchedulerAndSuccessState(t *testing.T) {
	s := setup(t)
	cfg := fixtureConfig(t)
	cfg.Schedule.Enabled = true
	cfg.Schedule.IntervalSeconds = 1
	activate(t, s, cfg)
	// A clean synthetic response is used to verify last_success and scheduling.
	clean := fetchFunc(func(ctx context.Context, c config.Config, emit func(collector.Page) error) error {
		return fixture.Fetcher{}.Fetch(ctx, c, func(p collector.Page) error {
			m := p.Payload.(map[string]any)
			m["vulnerabilities"] = m["vulnerabilities"].([]any)[:3]
			return emit(p)
		})
	})
	runner := engine.New(s, clean, "fixture")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runner.Schedule(ctx, 20*time.Millisecond); close(done) }()
	deadline := time.Now().Add(6 * time.Second)
	count := 0
	for time.Now().Before(deadline) {
		runs, e := s.Runs(ctx, cfg.ID, 100, 0)
		if e != nil {
			t.Fatal(e)
		}
		count = 0
		for _, r := range runs {
			if r.Outcome == "success" {
				count++
			}
		}
		if count >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	if count < 2 {
		t.Fatal("scheduler did not complete two runs", count)
	}
	health, e := s.Health(context.Background(), 100, 0)
	if e != nil || len(health) != 1 || health[0].LastSuccess == nil {
		t.Fatal("missing last success", e)
	}
	cfg.Schedule.Enabled = false
	activate(t, s, cfg)
	due, e := s.Due(context.Background())
	if e != nil || len(due) != 0 {
		t.Fatal("disabled schedule is due", due, e)
	}
}

func TestRecoveryFencesAbandonedRuns(t *testing.T) {
	s := setup(t)
	ctx := context.Background()
	cfg := fixtureConfig(t)
	activate(t, s, cfg)
	saved, err := s.Config(ctx, cfg.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	_, release, err := s.Lock(ctx, cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	r := model.Run{ID: "abandoned-test", Connector: cfg.ID, ConfigVersion: saved.Revision, ConfigHash: saved.Hash, Mode: "fixture", StartedAt: time.Now().UTC(), Outcome: "running"}
	if err = s.StartRun(ctx, r); err != nil {
		release()
		t.Fatal(err)
	}
	if err = s.Recover(ctx); err != nil {
		release()
		t.Fatal(err)
	}
	runs, _ := s.Runs(ctx, cfg.ID, 10, 0)
	if len(runs) != 1 || runs[0].Outcome != "running" {
		release()
		t.Fatal("active run interrupted")
	}
	release()
	if err = s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	runs, _ = s.Runs(ctx, cfg.ID, 10, 0)
	if runs[0].Outcome != "interrupted" {
		t.Fatal("abandoned run not recovered")
	}
	if err = s.SavePage(ctx, r.ID, cfg.ID, nil, nil); err == nil {
		t.Fatal("abandoned writer accepted")
	}
	now := time.Now().UTC()
	r.EndedAt = &now
	r.Outcome = "success"
	if err = s.FinishRun(ctx, r, 60); err == nil {
		t.Fatal("abandoned run changed success state")
	}
}
