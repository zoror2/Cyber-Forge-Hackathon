package store_test

import (
	"configbridge/internal/store"
	"configbridge/internal/testutil"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// Public sign-up stops at the account cap, even under concurrent requests;
// operator-created accounts are not capped.
func TestOpenSignupCap(t *testing.T) {
	db := testutil.Setup(t) // tenant-a, tenant-b
	ctx := context.Background()
	const max = 5
	var wg sync.WaitGroup
	var mu sync.Mutex
	created, closed := 0, 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := db.Store.CreateOpenAccount(ctx, fmt.Sprintf("open-%d", i), "Owner", "o@example.com", "hash", max)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case e == nil:
				created++
			case errors.Is(e, store.ErrSignupClosed):
				closed++
			default:
				t.Errorf("unexpected: %v", e)
			}
		}(i)
	}
	wg.Wait()
	if created != max-2 || closed != 10-(max-2) {
		t.Fatalf("created %d, closed %d; want %d created", created, closed, max-2)
	}
	if _, e := db.Store.CreateOpenAccount(ctx, "open-0", "Owner", "o@example.com", "hash", 100); !errors.Is(e, store.ErrExists) && e != nil {
		t.Fatalf("existing account: %v", e)
	}
	if _, e := db.Store.CreateAccount(ctx, "operator-made", "", "Owner", "o@example.com", "hash"); e != nil {
		t.Fatalf("operator path capped: %v", e)
	}
}
