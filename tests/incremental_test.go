package tests

import (
	"configbridge/internal/api"
	"configbridge/internal/egress"
	"configbridge/internal/engine"
	"configbridge/internal/runner"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"configbridge/pkg/model"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type changeFixture struct {
	mu       sync.Mutex
	now      time.Time
	rows     []map[string]any
	queries  []url.Values
	failPage int
	failure  string
	outside  bool
	blocked  chan struct{}
}

func changeRow(id, name string, at time.Time) map[string]any {
	return map[string]any{"id": id, "profile": map[string]any{"name": name}, "updated_at": at.Format(time.RFC3339Nano)}
}
func (f *changeFixture) clock() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
func (f *changeFixture) advance() {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := f.now
	f.now = f.now.Add(time.Hour)
	f.rows[1] = changeRow("2", "User Two updated", old.Add(20*time.Minute))
	f.rows = append(f.rows, changeRow("4", "User Four", old.Add(40*time.Minute)))
}
func (f *changeFixture) lastQuery() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries[len(f.queries)-1]
}
func (f *changeFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, e1 := time.Parse(time.RFC3339Nano, q.Get("updated_since"))
	until, e2 := time.Parse(time.RFC3339Nano, q.Get("updated_before"))
	if e1 != nil || e2 != nil {
		w.WriteHeader(400)
		return
	}
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("per_page"))
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 2
	}
	f.mu.Lock()
	f.queries = append(f.queries, q)
	failPage, failure, outside, blocked := f.failPage, f.failure, f.outside, f.blocked
	rows := []map[string]any{}
	for _, row := range f.rows {
		modified, err := time.Parse(time.RFC3339Nano, fmt.Sprint(row["updated_at"]))
		if outside || err != nil || (!modified.Before(since) && modified.Before(until)) {
			rows = append(rows, maps.Clone(row))
		}
	}
	f.mu.Unlock()
	if failPage == page {
		switch failure {
		case "json":
			fmt.Fprint(w, "not JSON")
			return
		case "hang":
			if blocked != nil {
				select {
				case blocked <- struct{}{}:
				default:
				}
			}
			<-r.Context().Done()
			return
		default:
			w.WriteHeader(500)
			return
		}
	}
	startAt := (page - 1) * size
	if raw := q.Get("offset"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			startAt = n
		}
	}
	start := min(startAt, len(rows))
	end := min(start+size, len(rows))
	json.NewEncoder(w).Encode(rows[start:end])
}
func incrementalEnv(t *testing.T) (*environment, *changeFixture) {
	t.Helper()
	e := setup(t)
	f := &changeFixture{now: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	for i := 1; i <= 3; i++ {
		f.rows = append(f.rows, changeRow(strconv.Itoa(i), fmt.Sprintf("User %d", i), f.now.Add(-time.Duration(4-i)*time.Hour)))
	}
	e.vendor.Close()
	e.vendor = httptest.NewTLSServer(f)
	t.Cleanup(e.vendor.Close)
	policy := egress.Policy{RootCAs: e.vendor.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, AllowPrivate: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	e.requests = engine.New(e.svc, policy, slog.New(slog.NewTextHandler(e.logs, nil)))
	e.runs = runner.NewWithClock(e.db.Store, e.requests, f.clock)
	h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc})
	if err != nil {
		t.Fatal(err)
	}
	e.api.Close()
	e.api = httptest.NewServer(h)
	t.Cleanup(e.api.Close)
	return e, f
}
func incrementalConfig(e *environment) config.Config {
	c := userConfig("incremental_users", e.vendor.URL+"/changes")
	c.Destination.Mapping["name"] = config.Field{Path: c.Destination.Mapping["name"].Path, Required: true}
	c.Pagination = engine.Pagination{Type: "page", PageParam: "page", SizeParam: "per_page", PageSize: 2, StartPage: 1}
	c.Retry.MaxAttempts = 1
	c.Incremental = &config.Incremental{Type: "time_window", StartTime: "2026-01-01T00:00:00Z", SinceParam: "updated_since", UntilParam: "updated_before", UpdatedAtPath: "updated_at"}
	return c
}
func syncState(t *testing.T, e *environment, tenant, id string) store.SyncState {
	t.Helper()
	var s store.SyncState
	if err := json.Unmarshal(e.request(t, tenant, "GET", "/connectors/"+id+"/sync-state", nil, 200), &s); err != nil {
		t.Fatal(err)
	}
	return s
}
func requireThrough(t *testing.T, e *environment, id string, want time.Time) {
	t.Helper()
	s := syncState(t, e, "tenant-a", id)
	if s.Watermark == nil || !s.Watermark.Through.Equal(want) {
		t.Fatal("checkpoint unexpectedly changed", s.Watermark, want)
	}
}

func TestIncrementalOnlyChangesRestartAndIsolation(t *testing.T) {
	e, f := incrementalEnv(t)
	c := incrementalConfig(e)
	e.save(t, "tenant-a", c, true)
	before := syncState(t, e, "tenant-a", c.ID)
	if before.Watermark != nil {
		t.Fatal("new config has a watermark")
	}
	first := e.run(t, "tenant-a", c.ID, 200)
	if first.Accepted != 3 || first.Incremental == nil || !first.Incremental.Committed {
		t.Fatal(first)
	}
	requireThrough(t, e, c.ID, f.clock())
	f.advance()
	second := e.run(t, "tenant-a", c.ID, 200)
	if second.Accepted != 2 || !second.Incremental.Since.Equal(first.Incremental.Until) {
		t.Fatal("did not fetch only changed users", second)
	}
	var records []model.User
	if err := json.Unmarshal(e.request(t, "tenant-a", "GET", "/records/users?source="+c.ID, nil, 200), &records); err != nil || len(records) != 4 {
		t.Fatal("upsert failed", err, len(records))
	}
	found := false
	for _, r := range records {
		if r.ID == "2" && r.Name != nil && *r.Name == "User Two updated" {
			found = true
		}
	}
	if !found {
		t.Fatal("changed record not updated")
	}
	f.mu.Lock()
	callsBefore := len(f.queries)
	f.mu.Unlock()
	empty := e.run(t, "tenant-a", c.ID, 200)
	if empty.Accepted != 0 || empty.Attempts != 0 || empty.Pages != 0 {
		t.Fatal("empty time window made a request", empty)
	}
	f.mu.Lock()
	if len(f.queries) != callsBefore {
		t.Error("empty time window called vendor")
	}
	f.now = f.now.Add(time.Hour)
	f.mu.Unlock()
	noChanges := e.run(t, "tenant-a", c.ID, 200)
	if noChanges.Accepted != 0 || noChanges.Attempts != 1 || !noChanges.Incremental.Committed {
		t.Fatal("empty response failed", noChanges)
	}
	// A new runtime store/runner resumes the durable checkpoint after restart.
	reopened, err := store.Open(context.Background(), e.db.AppDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Pool.Close()
	old := f.clock()
	f.mu.Lock()
	f.now = f.now.Add(time.Hour)
	f.rows = append(f.rows, changeRow("5", "After restart", old.Add(30*time.Minute)))
	f.mu.Unlock()
	next, err := runner.NewWithClock(reopened, e.requests, f.clock).Run(context.Background(), "tenant-a", c.ID, false, false)
	if err != nil || next.Accepted != 1 || !next.Incremental.Since.Equal(old) {
		t.Fatal("restart lost progress", next, err)
	}
	requireThrough(t, e, c.ID, f.clock())
	// History persists exactly the same bounds and decision as the response.
	var history []model.Run
	if err = json.Unmarshal(e.request(t, "tenant-a", "GET", "/runs?connector="+c.ID, nil, 200), &history); err != nil {
		t.Fatal(err)
	}
	found = false
	for _, r := range history {
		if r.ID == second.ID && r.Incremental != nil && r.Incremental.Committed && r.Incremental.Until.Equal(second.Incremental.Until) {
			found = true
		}
	}
	if !found {
		t.Fatal("incremental audit not persisted")
	}
	e.request(t, "tenant-b", "GET", "/connectors/"+c.ID+"/sync-state", nil, 404)
	e.save(t, "tenant-b", c, true)
	if syncState(t, e, "tenant-b", c.ID).Watermark != nil {
		t.Fatal("tenant B inherited checkpoint")
	}
	b := e.run(t, "tenant-b", c.ID, 200)
	if b.Accepted != 5 || b.Incremental.Since.Format(time.RFC3339) != c.Incremental.StartTime {
		t.Fatal("tenant isolation failed", b)
	}
}

func TestIncrementalAllSupportedPaginationAndBoundary(t *testing.T) {
	for _, style := range []string{"none", "page", "offset"} {
		t.Run(style, func(t *testing.T) {
			e, f := incrementalEnv(t)
			c := incrementalConfig(e)
			switch style {
			case "none":
				c.Pagination = engine.Pagination{Type: "none"}
				c.Request.Params = map[string]string{"per_page": "100"}
			case "offset":
				c.Pagination = engine.Pagination{Type: "offset", OffsetParam: "offset", SizeParam: "per_page", PageSize: 2}
			}
			boundary := f.clock()
			f.mu.Lock()
			f.rows = append(f.rows, changeRow("boundary", "At the cutoff", boundary))
			f.mu.Unlock()
			e.save(t, "tenant-a", c, true)
			first := e.run(t, "tenant-a", c.ID, 200)
			if first.Accepted != 3 {
				t.Fatal("exclusive upper boundary incorrectly included", first)
			}
			f.mu.Lock()
			f.now = f.now.Add(time.Minute)
			f.queries = nil
			f.mu.Unlock()
			next := e.run(t, "tenant-a", c.ID, 200)
			if next.Accepted != 1 {
				t.Fatal("record at previous cutoff was lost", next)
			}
			f.mu.Lock()
			queries := append([]url.Values(nil), f.queries...)
			f.mu.Unlock()
			for _, q := range queries {
				if q.Get("updated_since") != boundary.Format(time.RFC3339Nano) || q.Get("updated_before") != f.clock().Format(time.RFC3339Nano) {
					t.Fatal("page lost its time bounds", q)
				}
			}
		})
	}
}

func TestIncrementalFailuresAndQuarantineNeverAdvance(t *testing.T) {
	for _, scenario := range []string{"page500", "invalid_json", "invalid_timestamp", "bad_mapping", "outside_window", "page_cap", "record_cap"} {
		t.Run(scenario, func(t *testing.T) {
			e, f := incrementalEnv(t)
			c := incrementalConfig(e)
			if scenario == "page_cap" || scenario == "record_cap" {
				f.mu.Lock()
				f.rows = f.rows[:1]
				f.mu.Unlock()
				if scenario == "page_cap" {
					c.Limits.MaxPages = 1
				} else {
					c.Limits.MaxRecords = 1
				}
			}
			e.save(t, "tenant-a", c, true)
			first := e.run(t, "tenant-a", c.ID, 200)
			savedThrough := first.Incremental.Until
			if scenario == "page_cap" || scenario == "record_cap" {
				f.mu.Lock()
				f.now = f.now.Add(time.Hour)
				f.rows = append(f.rows, changeRow("2", "Two", savedThrough.Add(10*time.Minute)), changeRow("3", "Three", savedThrough.Add(20*time.Minute)))
				f.mu.Unlock()
			} else {
				f.advance()
			}
			f.mu.Lock()
			switch scenario {
			case "page500", "invalid_json":
				f.rows = append(f.rows, changeRow("5", "Five", savedThrough.Add(50*time.Minute)))
				f.failPage = 2
				if scenario == "invalid_json" {
					f.failure = "json"
				}
			case "invalid_timestamp":
				f.rows = append(f.rows, map[string]any{"id": "5", "profile": map[string]any{"name": "Five"}, "updated_at": "PRIVATE-INVALID-TIMESTAMP"})
			case "bad_mapping":
				f.rows[1]["profile"] = map[string]any{"name": nil}
			case "outside_window":
				f.outside = true
			}
			f.mu.Unlock()
			want := 502
			if scenario == "invalid_timestamp" || scenario == "bad_mapping" {
				want = 200
			}
			failed := e.run(t, "tenant-a", c.ID, want)
			if failed.Incremental == nil || failed.Incremental.Committed || failed.Outcome == "success" {
				t.Fatal("unsafe checkpoint decision", failed)
			}
			requireThrough(t, e, c.ID, savedThrough)
			if strings.Contains(e.logs.String(), "PRIVATE-INVALID-TIMESTAMP") {
				t.Fatal("invalid value leaked")
			}
			// Repair the source and replay from the same bookmark, deduplicating pages
			// that were committed before a later page failed.
			f.mu.Lock()
			f.failPage = 0
			f.failure = ""
			f.outside = false
			for _, row := range f.rows {
				if row["id"] == "5" {
					row["updated_at"] = savedThrough.Add(50 * time.Minute).Format(time.RFC3339)
				}
				if row["id"] == "2" {
					row["profile"] = map[string]any{"name": "Repaired Two"}
				}
			}
			f.mu.Unlock()
			if scenario == "page_cap" || scenario == "record_cap" {
				c.Limits.MaxPages = 10
				c.Limits.MaxRecords = 100
				e.save(t, "tenant-a", c, true)
			}
			recovered := e.run(t, "tenant-a", c.ID, 200)
			if recovered.Outcome != "success" || !recovered.Incremental.Committed {
				t.Fatal("replay failed", recovered)
			}
			requireThrough(t, e, c.ID, f.clock())
			var records []model.User
			if err := json.Unmarshal(e.request(t, "tenant-a", "GET", "/records/users?source="+c.ID, nil, 200), &records); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			expected := len(f.rows)
			f.mu.Unlock()
			if len(records) != expected {
				t.Fatal("lost or duplicated records", len(records), expected)
			}
		})
	}
}

func TestIncrementalPreviewOverlapResetAndCorruptState(t *testing.T) {
	e, f := incrementalEnv(t)
	c := incrementalConfig(e)
	c.Incremental.OverlapSeconds = 60
	revision := e.save(t, "tenant-a", c, true)
	body := []byte(fmt.Sprintf(`{"revision":%d}`, revision))
	e.request(t, "tenant-a", "POST", "/configs/"+c.ID+"/test", body, 200)
	if syncState(t, e, "tenant-a", c.ID).Watermark != nil {
		t.Fatal("preview advanced bookmark")
	}
	first := e.run(t, "tenant-a", c.ID, 200)
	cp := first.Incremental.Until
	f.mu.Lock()
	f.now = f.now.Add(time.Hour)
	f.rows = append(f.rows, changeRow("late", "Late arrival", cp.Add(-30*time.Second)))
	f.mu.Unlock()
	late := e.run(t, "tenant-a", c.ID, 200)
	if late.Accepted != 1 || !late.Incremental.Since.Equal(cp.Add(-time.Minute)) {
		t.Fatal("overlap missed late arrival", late)
	}
	// A config revision change conservatively replays the initial range.
	c.Name = "Reviewed mapping revision"
	e.save(t, "tenant-a", c, true)
	reset := e.run(t, "tenant-a", c.ID, 200)
	if !reset.Incremental.Reset || reset.Accepted != 4 || reset.Incremental.Since.Format(time.RFC3339) != c.Incremental.StartTime {
		t.Fatal("config reused incompatible bookmark", reset)
	}
	through := reset.Incremental.Until
	f.mu.Lock()
	f.now = f.now.Add(-2 * time.Hour)
	f.mu.Unlock()
	back := e.run(t, "tenant-a", c.ID, 200)
	if back.Incremental.Until.Before(through) {
		t.Fatal("clock regression rewound checkpoint")
	}
	requireThrough(t, e, c.ID, through)
	// Corrupt state fails closed rather than silently skipping to a new boundary.
	_, err := e.db.Admin.Exec(context.Background(), "UPDATE "+e.db.Schema+".sync_state SET watermark='{\"version\":99,\"config_hash\":\"bad\",\"through\":\"2026-10-31T00:00:00Z\"}' WHERE tenant_id='tenant-a' AND connector=$1", c.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.request(t, "tenant-a", "POST", "/connectors/"+c.ID+"/run", nil, 503)
}

func TestIncrementalCancellationAndFinalizationAreSafe(t *testing.T) {
	e, f := incrementalEnv(t)
	c := incrementalConfig(e)
	e.save(t, "tenant-a", c, true)
	first := e.run(t, "tenant-a", c.ID, 200)
	cp := first.Incremental.Until
	f.advance()
	f.mu.Lock()
	f.rows = append(f.rows, changeRow("5", "Five", cp.Add(50*time.Minute)))
	f.failPage = 2
	f.failure = "hang"
	f.blocked = make(chan struct{}, 1)
	blocked := f.blocked
	f.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		run model.Run
		err error
	}
	done := make(chan result, 1)
	go func() { r, err := e.runs.Run(ctx, "tenant-a", c.ID, false, false); done <- result{r, err} }()
	select {
	case <-blocked:
		cancel()
	case <-time.After(5 * time.Second):
		t.Fatal("second page not reached")
	}
	stopped := <-done
	if stopped.err == nil || stopped.run.Outcome != "interrupted" || stopped.run.Incremental.Committed {
		t.Fatal("cancel advanced bookmark", stopped)
	}
	requireThrough(t, e, c.ID, cp)
	f.mu.Lock()
	f.failPage = 0
	f.failure = ""
	f.mu.Unlock()
	// Fail the last DB operation: both the terminal run update and checkpoint
	// must roll back, rather than claiming a committed watermark in history.
	schema := e.db.Schema
	_, err := e.db.Admin.Exec(context.Background(), "CREATE FUNCTION "+schema+".reject_sync() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''synthetic finalization failure''; END'; CREATE TRIGGER fail_sync BEFORE UPDATE ON "+schema+".sync_state FOR EACH ROW EXECUTE FUNCTION "+schema+".reject_sync()")
	if err != nil {
		t.Fatal(err)
	}
	failed := e.run(t, "tenant-a", c.ID, 502)
	if failed.Error != "run_finalization_failed" || failed.Incremental.Committed {
		t.Fatal("unsafe finalization", failed)
	}
	requireThrough(t, e, c.ID, cp)
	if _, err = e.db.Admin.Exec(context.Background(), "DROP TRIGGER fail_sync ON "+schema+".sync_state"); err != nil {
		t.Fatal(err)
	}
	if err = e.db.Store.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered := e.run(t, "tenant-a", c.ID, 200)
	if recovered.Accepted != 3 {
		t.Fatal("restart failed to replay failed pages", recovered)
	}
	requireThrough(t, e, c.ID, f.clock())
	// A completed/stale worker cannot publish a later made-up checkpoint.
	stale := first
	copy := *first.Incremental
	copy.Until = f.clock().Add(time.Hour)
	stale.Incremental = &copy
	if err = e.db.Store.ForTenant("tenant-a").FinishRun(context.Background(), stale, 60); err == nil {
		t.Fatal("stale worker committed")
	}
	requireThrough(t, e, c.ID, f.clock())
}
