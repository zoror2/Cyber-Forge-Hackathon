package store_test

import (
	"configbridge/internal/insights"
	"configbridge/internal/store"
	"configbridge/internal/testutil"
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"sync"
	"sync/atomic"
	"testing"
)

func TestTokenReservationsAtomicPersistentScopedAndIdempotent(t *testing.T) {
	db := testutil.Setup(t)
	ctx := context.Background()
	scope := db.Store.ForTenant("tenant-a")
	var wg sync.WaitGroup
	var won atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := scope.ReserveMeteredAI(ctx, 100, 2*store.AIReservation, store.AIAudit{RequestID: fmt.Sprintf("r%d", i), Actor: "test", SourceID: "aggregate_siem", Provider: "fixture", Model: "fixture", PromptVersion: "v1"}, "siem_explanation")
			if err == nil {
				won.Add(1)
			} else if !errors.Is(err, store.ErrAIBudget) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if won.Load() != 2 {
		t.Fatal("concurrent overspend", won.Load())
	}
	u, e := scope.AIConsumption(ctx)
	if e != nil || u.UnreportedReserved != 2*store.AIReservation || u.Requests != 2 {
		t.Fatal(u, e)
	}
	id := u.Recent[0].ID
	usage := insights.Usage{Known: true, Input: 80, Output: 20, Total: 100}
	if e = scope.FinishTokens(ctx, id, "explained", usage); e != nil {
		t.Fatal(e)
	}
	if e = scope.FinishTokens(ctx, id, "explained", usage); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("duplicate finalization changed totals", e)
	}
	other := db.Store.ForTenant("tenant-b")
	if e = other.FinishTokens(ctx, u.Recent[1].ID, "explained", usage); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("cross-tenant finalize", e)
	}
	if e = other.ReserveMeteredAI(ctx, 1, store.AIReservation, store.AIAudit{RequestID: "own", Actor: "test", SourceID: "aggregate_siem", Provider: "fixture", Model: "fixture", PromptVersion: "v1"}, "siem_explanation"); e != nil {
		t.Fatal(e)
	}
	e = other.ReserveMeteredAI(ctx, 1, store.AIReservation, store.AIAudit{RequestID: "rejected", Actor: "test"}, "siem_explanation")
	if !errors.Is(e, store.ErrAIBudget) {
		t.Fatal(e)
	}
	if e = other.WithTx(ctx, func(tx pgx.Tx) error {
		var n int
		err := tx.QueryRow(ctx, "SELECT count(*) FROM ai_audit").Scan(&n)
		if n != 1 {
			t.Fatal("rejected audit or cross-tenant leak", n)
		}
		return err
	}); e != nil {
		t.Fatal(e)
	}
	reopened, e := store.Open(ctx, db.AppDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Pool.Close()
	again, e := reopened.ForTenant("tenant-a").AIConsumption(ctx)
	if e != nil || again.ReportedTokens != 100 || again.UnreportedReserved != store.AIReservation {
		t.Fatal("restart lost usage", again, e)
	}
	if _, e = db.Admin.Exec(ctx, "UPDATE "+db.Schema+".ai_requests SET created_at=created_at-interval '1 day' WHERE tenant_id='tenant-a'"); e != nil {
		t.Fatal(e)
	}
	reset, e := scope.AIConsumption(ctx)
	if e != nil || reset.Requests != 0 {
		t.Fatal("UTC day reset", reset, e)
	}
}
