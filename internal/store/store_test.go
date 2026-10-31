package store_test

import (
	"configbridge/internal/store"
	"configbridge/internal/testutil"
	"configbridge/pkg/config"
	"configbridge/pkg/mapping"
	"configbridge/pkg/model"
	"configbridge/pkg/ocsf"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"os"
	"testing"
	"time"
)

// Guard: any table added later must have forced RLS and a policy, or this fails.
// Only the migration bookkeeping table is exempt (it holds no tenant data).
func TestEveryTableHasForcedRLS(t *testing.T) {
	ctx := context.Background()
	db := testutil.Setup(t)
	rows, e := db.Admin.Query(ctx, `SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
		(SELECT count(*) FROM pg_policy p WHERE p.polrelid=c.oid)
		FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname=$1 AND c.relkind IN ('r','p') ORDER BY 1`, db.Schema)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var name string
		var enabled, forced bool
		var policies int
		if e = rows.Scan(&name, &enabled, &forced, &policies); e != nil {
			t.Fatal(e)
		}
		seen++
		if name == "schema_migrations" {
			continue
		}
		if !enabled || !forced || policies == 0 {
			t.Errorf("table %s: rls=%v forced=%v policies=%d", name, enabled, forced, policies)
		}
	}
	if seen < 9 {
		t.Fatal("schema not migrated?", seen)
	}
}

func TestTenantRLSAndUpsert(t *testing.T) {
	db := testutil.Setup(t)
	ctx := context.Background()
	if s, e := store.Open(ctx, db.AdminDSN); e == nil {
		s.Pool.Close()
		t.Fatal("superuser accepted as runtime")
	}
	b, _ := os.ReadFile("../../configs/fixture_events.json")
	c, issues := config.Decode(b)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		scope := db.Store.ForTenant(tenant)
		saved, e := scope.SaveConfig(ctx, c)
		if e != nil {
			t.Fatal(e)
		}
		if e = scope.Activate(ctx, c.ID, saved.Revision); e != nil {
			t.Fatal(e)
		}
		r := model.Run{TenantID: tenant, ID: "same-run", Connector: c.ID, ConfigVersion: 1, ConfigHash: saved.Hash, Mode: "live", StartedAt: time.Now().UTC()}
		if e = scope.StartRun(ctx, r); e != nil {
			t.Fatal(e)
		}
		rec, bad := mapping.Map(map[string]any{"cveID": "same-id", "dates": map[string]any{"added": "2026-10-31"}, "shortDescription": tenant}, c, tenant, time.Now().UTC(), 0)
		if bad != nil {
			t.Fatal(bad)
		}
		for i := 0; i < 2; i++ {
			if e = scope.SavePage(ctx, r.ID, c.ID, []model.Record{rec}, nil); e != nil {
				t.Fatal(e)
			}
		}
		rows, e := scope.Records(ctx, 2002, "", 100, 0)
		if e != nil || len(rows) != 1 {
			t.Fatal("upsert failed", e, len(rows))
		}
		var payload map[string]any
		json.Unmarshal(rows[0], &payload)
		if ocsf.Get(payload, "metadata.tenant_uid") != tenant || ocsf.Get(payload, "finding_info.title") != tenant {
			t.Fatal("cross-tenant record")
		}
	}
	a := db.Store.ForTenant("tenant-a")
	e := a.WithTx(ctx, func(tx pgx.Tx) error {
		var n int
		if e := tx.QueryRow(ctx, "SELECT COUNT(*) FROM ocsf_records").Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			t.Fatal("RLS failed without tenant WHERE", n)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	e = a.WithTx(ctx, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, "UPDATE configs SET status='approved' WHERE tenant_id='tenant-b'")
		if e == nil && tag.RowsAffected() != 0 {
			t.Fatal("cross-tenant update")
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	e = a.WithTx(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO credentials_meta(tenant_id,name,allowed_host,backend)VALUES('tenant-b','stolen','api.example.com','local')")
		return e
	})
	if e == nil {
		t.Fatal("cross-tenant insert accepted")
	}
	bscope := db.Store.ForTenant("tenant-b")
	other := c
	other.ID = "only-b"
	if _, e = bscope.SaveConfig(ctx, other); e != nil {
		t.Fatal(e)
	}
	if _, e = a.Config(ctx, other.ID, false); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("cross-tenant config visible")
	}
	// PRD common schema view: PRD field names, still tenant-isolated (security_invoker)
	ev, e := a.View(ctx, "events", "", 100, 0)
	if e != nil || len(ev) != 1 {
		t.Fatal("events view", e, len(ev))
	}
	var row map[string]any
	json.Unmarshal(ev[0], &row)
	if row["id"] != "same-id" || row["description"] != "tenant-a" || row["tenant_id"] != "tenant-a" ||
		row["type"] != "Vulnerability Finding" || row["source"] == nil || row["fetched_at"] == nil {
		t.Fatal("events view row wrong or cross-tenant", row)
	}
	if _, e = a.View(ctx, "ocsf_records; --", "", 1, 0); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("non-whitelisted view accepted", e)
	}
	e = a.WithTx(ctx, func(tx pgx.Tx) error {
		var n int
		if e := tx.QueryRow(ctx, "SELECT COUNT(*) FROM events").Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			t.Fatal("view bypassed RLS", n)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	// saving the identical config again makes no new revision
	same, e := a.SaveConfig(ctx, c)
	if e != nil || !same.Unchanged || same.Revision != 1 || same.Status != "live" {
		t.Fatal("identical save created a duplicate revision", same, e)
	}
	// a real change makes a second draft: the list shows it and still names the live one
	c.Name += " v2"
	if _, e = a.SaveConfig(ctx, c); e != nil {
		t.Fatal(e)
	}
	list, e := a.Configs(ctx, 100, 0)
	if e != nil || len(list) != 1 || list[0].ID != c.ID || list[0].Revision != 2 || list[0].Status != "draft" ||
		list[0].Live != 1 || list[0].Class != "vulnerability_finding" || list[0].Hash == "" {
		t.Fatal("config list wrong (or tenant-b's only-b leaked)", list, e)
	}
	var n int
	if e = db.Store.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM ocsf_records").Scan(&n); e != nil || n != 0 {
		t.Fatal("tenant setting leaked into pooled session", n, e)
	}
	tenant, e := db.Store.Authenticate(ctx, "tenant-a-key-tenant-a-key-tenant-a-key-tenant-a-key-")
	if e != nil || tenant != "tenant-a" {
		t.Fatal("hashed authentication failed", tenant, e)
	}
	if _, e = db.Store.Authenticate(ctx, "wrong"); e == nil {
		t.Fatal("bad API key accepted")
	}
}
