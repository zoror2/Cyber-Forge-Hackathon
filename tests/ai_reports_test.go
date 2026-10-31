package tests

import (
	"configbridge/internal/api"
	"configbridge/internal/insights"
	"configbridge/internal/store"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAIReportsLedgerIsolationOperatorAndUTCBoundaries(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	today := time.Now().UTC().Truncate(24 * time.Hour)
	day := today.Format(time.DateOnly)
	seed := func(tenant, id, operation, outcome string, in, out int64, known bool, created time.Time) {
		t.Helper()
		s := e.db.Store.ForTenant(tenant)
		if err := s.ReserveMeteredAI(ctx, 100, 4000000, store.AIAudit{RequestID: id, Actor: "PRIVATE_ACTOR_SENTINEL", SourceID: "PRIVATE_SOURCE_SENTINEL", Provider: "fixture", Model: "fixture-model", PromptVersion: "v1"}, operation); err != nil {
			t.Fatal(err)
		}
		if outcome != "reserved" {
			if err := s.FinishTokens(ctx, id, outcome, insights.Usage{Known: known, Input: in, Output: out, Total: in + out}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := e.db.Admin.Exec(ctx, "UPDATE "+pgx.Identifier{e.db.Schema, "ai_requests"}.Sanitize()+" SET created_at=$1,finished_at=CASE WHEN finished_at IS NULL THEN NULL ELSE $1::timestamptz+interval '2 seconds' END WHERE tenant_id=$2 AND request_id=$3", created, tenant, id); err != nil {
			t.Fatal(err)
		}
	}
	seed("tenant-a", "same-id", "config_draft", "drafted", 80, 20, true, today)
	seed("tenant-a", "rejected", "config_draft", "validation_rejected", 40, 10, true, today)
	seed("tenant-a", "unknown", "siem_explanation", "provider_failed", 0, 0, false, today)
	seed("tenant-a", "pending", "siem_explanation", "reserved", 0, 0, false, today)
	seed("tenant-b", "same-id", "config_draft", "drafted", 20, 5, true, today)
	seed("tenant-a", "utc-previous", "config_draft", "drafted", 6, 1, true, today.Add(-time.Microsecond))
	seed("tenant-a", "utc-next", "config_draft", "drafted", 8, 1, true, today.AddDate(0, 0, 1))
	operator := strings.Repeat("synthetic-operator-", 3)
	h, err := api.New(&api.API{Store: e.db.Store, Engine: e.runs, Secrets: e.svc, OperatorToken: operator, Limits: &api.Limits{}})
	if err != nil {
		t.Fatal(err)
	}
	e.api.Close()
	e.api = httptest.NewServer(h)
	defer e.api.Close()
	query := "?from=" + day + "&to=" + day
	get := func(path, token, origin string, status int) (report store.AIReport, raw string) {
		t.Helper()
		req, _ := http.NewRequest("GET", e.api.URL+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.Header.Set("X-Tenant-ID", "tenant-b")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		raw = string(b)
		if r.StatusCode != status {
			t.Fatalf("%s status=%d want=%d body=%s", path, r.StatusCode, status, raw)
		}
		if r.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("usage report cached")
		}
		if status == 200 {
			if err := json.Unmarshal(b, &report); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	a, raw := get("/ai/consumption"+query, key("tenant-a"), "", 200)
	if a.Summary.Requests != 4 || a.Summary.ReportedTokens != 150 || a.Summary.Input != 120 || a.Summary.Output != 30 || a.Summary.UnreportedReserved != 80000 || a.Summary.Failed != 2 || a.Summary.Unknown != 1 || a.Summary.Pending != 1 || a.CustomerCount != 1 || a.Customers[0].Customer != "tenant-a" || len(a.Daily) != 1 || a.Daily[0].ReportedTokens != 150 {
		t.Fatalf("wrong ledger totals: %+v", a)
	}
	for _, marker := range []string{"PRIVATE_ACTOR_SENTINEL", "PRIVATE_SOURCE_SENTINEL", "tenant-b", "utc-previous", "utc-next", "password", "prompt_version"} {
		if strings.Contains(raw, marker) {
			t.Fatal("report leaked/exceeded range", marker)
		}
	}
	for _, r := range a.Requests {
		if r.ID == "unknown" && (r.Total != nil || r.FinishedAt == nil || r.DurationMS == nil) {
			t.Fatal("unknown conflated with zero or pending")
		}
		if r.ID == "pending" && (r.Total != nil || r.FinishedAt != nil || r.DurationMS != nil) {
			t.Fatal("pending conflated with finished")
		}
		if r.ID == "same-id" && (r.Total == nil || *r.Total != 100 || *r.DurationMS != 2000) {
			t.Fatal("known usage or duration lost")
		}
	}
	b, _ := get("/ai/consumption"+query, key("tenant-b"), "", 200)
	if b.Summary.ReportedTokens != 25 || b.Summary.Requests != 1 {
		t.Fatal("cross customer ledger", b)
	}
	all, _ := get("/operator/ai/consumption"+query, operator, "", 200)
	if all.CustomerCount != 2 || all.Summary.ReportedTokens != 175 || all.Summary.Requests != 5 || len(all.Customers) != 2 {
		t.Fatal("operator totals", all)
	}
	one, _ := get("/operator/ai/consumption"+query+"&customer=tenant-b", operator, "", 200)
	if one.CustomerCount != 1 || one.Summary.ReportedTokens != 25 {
		t.Fatal("operator filter", one)
	}
	empty, _ := get("/operator/ai/consumption"+query+"&customer=nonexistent", operator, "", 200)
	if empty.CustomerCount != 0 || empty.Summary.Requests != 0 || len(empty.Requests) != 0 || len(empty.Daily) != 1 {
		t.Fatal("empty report", empty)
	}
	first, _ := get("/operator/ai/consumption"+query+"&limit=1&offset=2", operator, "", 200)
	second, _ := get("/operator/ai/consumption"+query+"&limit=1&offset=3", operator, "", 200)
	if len(first.Requests) != 1 || len(second.Requests) != 1 || first.Summary.Requests != 5 || first.Requests[0].Customer == second.Requests[0].Customer && first.Requests[0].ID == second.Requests[0].ID {
		t.Fatal("unstable or incorrect pagination")
	}
	get("/operator/ai/consumption", key("tenant-a"), "", 401)
	get("/operator/ai/consumption", key("tenant-b"), "", 401)
	get("/operator/ai/consumption", "", "", 401)
	get("/operator/ai/consumption", operator, "https://foreign.invalid", 403)
	get("/ai/consumption", "", "", 401)
	for _, bad := range []string{"?from=2026-02-30", query + "&customer=tenant-b", query + "&tenant=tenant-b", query + "&limit=0", query + "&limit=101", query + "&offset=-1", query + "&offset=100001", query + "&limit=2&limit=3", "?from=2026-01-01&to=2026-05-01", "?from=" + day + "&to=2020-01-01"} {
		get("/ai/consumption"+bad, key("tenant-a"), "", 400)
	}
	get("/operator/ai/consumption"+query+"&customer=%27%3Bselect", operator, "", 400)
	// The unprivileged report function retains RLS even if its SQL caller
	// supplies a foreign tenant id. The operator wrapper is a separate API gate.
	err = e.db.Store.ForTenant("tenant-a").WithTx(ctx, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT ai_consumption_report($1::date,$1::date,'tenant-b',50,0)", day).Scan(&raw); err != nil {
			return err
		}
		var r store.AIReport
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		if r.CustomerCount != 0 || r.Summary.Requests != 0 {
			return fmt.Errorf("report function bypassed RLS")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// New reports survive reopening the runtime pool; they are not UI counters.
	reopened, err := store.Open(ctx, e.db.AppDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Pool.Close()
	again, err := reopened.OperatorAIReport(ctx, day, day, "", 100, 0)
	if err != nil || again.Summary.ReportedTokens != 175 {
		t.Fatal("lost persistent report", again, err)
	}
}
