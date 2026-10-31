package store_test

import (
	"configbridge/internal/store"
	"configbridge/internal/testutil"
	"configbridge/pkg/config"
	"configbridge/pkg/mapping"
	"configbridge/pkg/model"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"os"
	"testing"
	"time"
)

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
		rows, e := scope.Records(ctx, "event", "", 100, 0)
		if e != nil || len(rows) != 1 {
			t.Fatal("upsert failed", e, len(rows))
		}
		var payload map[string]any
		json.Unmarshal(rows[0], &payload)
		if payload["tenant_id"] != tenant || payload["description"] != tenant {
			t.Fatal("cross-tenant record")
		}
	}
	a := db.Store.ForTenant("tenant-a")
	e := a.WithTx(ctx, func(tx pgx.Tx) error {
		var n int
		if e := tx.QueryRow(ctx, "SELECT COUNT(*) FROM events").Scan(&n); e != nil {
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
	var n int
	if e = db.Store.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM events").Scan(&n); e != nil || n != 0 {
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
