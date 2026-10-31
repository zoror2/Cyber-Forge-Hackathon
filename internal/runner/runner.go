// Package runner coordinates authenticated live DB configs, Member A's engine,
// mapping and storage. No code path accepts a request-body config for execution.
package runner

import (
	"configbridge/internal/egress"
	"configbridge/internal/engine"
	"configbridge/internal/store"
	"configbridge/pkg/mapping"
	"configbridge/pkg/model"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type Fetcher interface {
	Fetch(context.Context, engine.Connector, func(engine.Page) error) (engine.Result, error)
}

var ErrLimit = errors.New("collection_limit")
var ErrNotDue = errors.New("not_due")

type Runner struct {
	Store   *store.Store
	Fetcher Fetcher
	slots   chan struct{}
	mu      sync.Mutex
	tenants map[string]bool
}

func New(s *store.Store, f Fetcher) *Runner {
	return &Runner{Store: s, Fetcher: f, slots: make(chan struct{}, 2), tenants: map[string]bool{}}
}
func (r *Runner) capacity(tenant string) (func(), bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tenants[tenant] {
		return nil, false
	}
	select {
	case r.slots <- struct{}{}:
	default:
		return nil, false
	}
	r.tenants[tenant] = true
	return func() { r.mu.Lock(); delete(r.tenants, tenant); <-r.slots; r.mu.Unlock() }, true
}
func (r *Runner) Run(ctx context.Context, tenant, id string, test, scheduled bool) (model.Run, error) {
	release, ok := r.capacity(tenant)
	if !ok {
		return model.Run{}, store.ErrBusy
	}
	defer release()
	scope := r.Store.ForTenant(tenant)
	ctx, unlock, e := scope.Lock(ctx, id)
	if e != nil {
		return model.Run{}, e
	}
	defer unlock()
	saved, e := scope.Config(ctx, id, true)
	if e != nil {
		return model.Run{}, e
	}
	c := saved.Config
	if len(c.Validate()) > 0 {
		return model.Run{}, errors.New("invalid_config")
	}
	if scheduled {
		due, e := scope.IsDue(ctx, id)
		if e != nil {
			return model.Run{}, e
		}
		if !due || !c.Schedule.Enabled {
			return model.Run{}, ErrNotDue
		}
	}
	seconds := c.Limits.MaxRunSeconds
	if test && seconds > 30 {
		seconds = 30
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	b := make([]byte, 16)
	if _, e = rand.Read(b); e != nil {
		return model.Run{}, errors.New("run_id_unavailable")
	}
	run := model.Run{TenantID: tenant, ID: hex.EncodeToString(b), Connector: id, ConfigVersion: saved.Revision, ConfigHash: saved.Hash, Mode: "live", StartedAt: time.Now().UTC(), Outcome: "running"}
	if test {
		run.Mode = "test"
	}
	if !test {
		if e = scope.StartRun(ctx, run); e != nil {
			return model.Run{}, e
		}
	}
	sampleDone := errors.New("sample_complete")
	result, e := r.Fetcher.Fetch(ctx, c.Connector(tenant), func(page engine.Page) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		items := page.Items
		if test && len(items) > 100 {
			items = items[:100]
		}
		if len(items) > c.Limits.MaxRecords-run.Received {
			return ErrLimit
		}
		records := []model.Record{}
		bad := []model.Rejection{}
		now := time.Now().UTC()
		for i, row := range items {
			if e := ctx.Err(); e != nil {
				return e
			}
			rec, q := mapping.Map(row, c, tenant, now, run.Received+i)
			if q != nil {
				q.Page = page.Number
				bad = append(bad, *q)
			} else {
				records = append(records, rec)
			}
		}
		if !test {
			if e := scope.SavePage(ctx, run.ID, id, records, bad); e != nil {
				return errors.New("storage_failed")
			}
		}
		run.Pages++
		run.Received += len(items)
		run.Accepted += len(records)
		run.Quarantined += len(bad)
		if test {
			return sampleDone
		}
		return nil
	})
	// Counts include failed logical API attempts; OAuth exchanges are separate.
	run.Attempts = result.Attempts
	if test && errors.Is(e, sampleDone) {
		e = nil
	}
	if e == nil && run.Pages == 0 {
		e = errors.New("no_pages")
	}
	run.Outcome = "success"
	if run.Quarantined > 0 {
		run.Outcome = "completed_with_errors"
	}
	if e != nil {
		run.Outcome = "failed"
		run.Error = Category(e)
		if run.Pages > 0 || errors.Is(e, ErrLimit) || errors.Is(e, engine.ErrPageLimit) {
			run.Outcome = "incomplete"
		}
		if errors.Is(e, context.Canceled) {
			run.Outcome = "interrupted"
		}
	}
	end := time.Now().UTC()
	run.EndedAt = &end
	if !test {
		finish, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if e2 := scope.FinishRun(finish, run, c.Schedule.IntervalSeconds); e2 != nil {
			run.Outcome = "incomplete"
			run.Error = "run_finalization_failed"
			return run, errors.New(run.Error)
		}
	}
	return run, e
}
func Category(e error) string {
	// Credential problems first: binding_mismatch is also an egress block, and
	// 401/403 are also StatusErrors, but the credential status is more useful.
	var ae *engine.AuthError
	if errors.As(e, &ae) {
		switch ae.Status {
		case engine.StatusNeedsReauth, engine.StatusInsufficientPermissions:
			return "auth_failed"
		default: // missing, incomplete, binding_mismatch
			return "credential_" + ae.Status
		}
	}
	switch {
	case errors.Is(e, egress.ErrBlocked):
		return "destination_denied"
	case errors.Is(e, engine.ErrTooLarge):
		return "response_too_large"
	case errors.Is(e, engine.ErrPageLimit), errors.Is(e, ErrLimit):
		return "collection_limit"
	case errors.Is(e, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(e, context.Canceled):
		return "interrupted"
	}
	var status *engine.StatusError
	if errors.As(e, &status) {
		switch status.Code {
		case 401, 403:
			return "auth_failed"
		case 429:
			return "rate_limited"
		default:
			return "vendor_http_failed"
		}
	}
	return "collection_failed"
}
func (r *Runner) Schedule(ctx context.Context, tick time.Duration) {
	jobs := make(chan store.Job, 10)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j, ok := <-jobs:
					if !ok {
						return
					}
					r.Run(ctx, j.Tenant, j.Connector, false, true)
				}
			}
		}()
	}
	timer := time.NewTicker(tick)
	defer timer.Stop()
	defer wg.Wait()
	defer close(jobs)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			list, e := r.Store.Jobs(ctx, false)
			if e != nil {
				continue
			}
			for _, j := range list {
				select {
				case jobs <- j:
				default: /* remains due */
				}
			}
		}
	}
}
