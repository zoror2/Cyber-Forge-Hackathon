package store_test

import (
	"configbridge/internal/store"
	"configbridge/internal/testutil"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAIBudgetIsAtomicPersistentAndTenantScoped(t *testing.T) {
	db := testutil.Setup(t)
	scope := db.Store.ForTenant("tenant-a")
	ctx := context.Background()
	var wg sync.WaitGroup
	var succeeded atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := scope.ReserveAI(ctx, 3, store.AIAudit{RequestID: "request", Actor: "api_key:fixture", SourceID: "fixture", SourceHash: "hash", Provider: "mock", Model: "fixture", PromptVersion: "v1"})
			if err == nil {
				succeeded.Add(1)
			} else if !errors.Is(err, store.ErrAIBudget) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if succeeded.Load() != 3 {
		t.Fatal("concurrent calls bypassed budget", succeeded.Load())
	}
	reopened, err := store.Open(ctx, db.AppDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Pool.Close()
	if err = reopened.ForTenant("tenant-a").ReserveAI(ctx, 3, store.AIAudit{}); !errors.Is(err, store.ErrAIBudget) {
		t.Fatal("budget lost after restart", err)
	}
	b := db.Store.ForTenant("tenant-b")
	if err = b.ReserveAI(ctx, 3, store.AIAudit{}); err != nil {
		t.Fatal("other tenant starved", err)
	}
	// Previous UTC-day usage does not consume today's allowance.
	if _, err = db.Admin.Exec(ctx, "UPDATE "+db.Schema+".ai_usage SET day=day-1 WHERE tenant_id='tenant-a'"); err != nil {
		t.Fatal(err)
	}
	if err = scope.ReserveAI(ctx, 3, store.AIAudit{}); err != nil {
		t.Fatal("budget failed to reset", err)
	}
	if err = b.WithTx(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM ai_audit").Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Error("RLS exposed another tenant's audit", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
