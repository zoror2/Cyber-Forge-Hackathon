package store_test

import (
	"configbridge/internal/store"
	"configbridge/internal/testutil"
	"context"
	"errors"
	"testing"
)

func TestSchemaAndTenantLockNamespaces(t *testing.T) {
	first, second := testutil.Setup(t), testutil.Setup(t)
	ctx := context.Background()
	a := first.Store.ForTenant("tenant-a")
	_, release, e := a.Lock(ctx, "same-connector")
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if _, _, e = a.Lock(ctx, "same-connector"); !errors.Is(e, store.ErrBusy) {
		t.Fatal("same connector overlapped")
	}
	for _, scope := range []store.Scope{first.Store.ForTenant("tenant-b"), second.Store.ForTenant("tenant-a")} {
		_, unlock, e := scope.Lock(ctx, "same-connector")
		if e != nil {
			t.Fatal("independent tenant/schema blocked", e)
		}
		unlock()
	}
}
