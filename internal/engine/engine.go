// Package engine orchestrates DB-only live configs using Member A's Fetcher.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/zoror2/Cyber-Forge-Hackathon/internal/store"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/collector"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/mapping"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/model"
)

var ErrLimit = errors.New("collection_limit")
var ErrNotDue = errors.New("not_due")

type Engine struct {
	Store   *store.Store
	Fetcher collector.Fetcher
	Mode    string
	slots   chan struct{}
}

func New(s *store.Store, f collector.Fetcher, mode string) *Engine {
	return &Engine{Store: s, Fetcher: f, Mode: mode, slots: make(chan struct{}, 2)}
}

// Run never accepts a config or a URL: it reloads the current live DB version.
// TestConnection shares the lock but does not persist records, runs or sync state.
func (e *Engine) Run(ctx context.Context, id string, test, scheduled bool) (model.Run, error) {
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		return model.Run{}, store.ErrBusy
	}
	ctx, unlock, err := e.Store.Lock(ctx, id)
	if err != nil {
		return model.Run{}, err
	}
	defer unlock()
	saved, err := e.Store.Config(ctx, id, true)
	if err != nil {
		return model.Run{}, err
	}
	if scheduled {
		due, err := e.Store.IsDue(ctx, id)
		if err != nil {
			return model.Run{}, err
		}
		if !due || !saved.Config.Schedule.Enabled {
			return model.Run{}, ErrNotDue
		}
	}
	c := saved.Config
	if len(c.Validate()) > 0 {
		return model.Run{}, errors.New("invalid_config")
	}
	seconds := c.Limits.MaxRunSeconds
	if test && seconds > 30 {
		seconds = 30
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return model.Run{}, errors.New("run_id_unavailable")
	}
	r := model.Run{ID: hex.EncodeToString(random), Connector: id, ConfigVersion: saved.Revision, ConfigHash: saved.Hash, Mode: e.Mode, StartedAt: time.Now().UTC(), Outcome: "running"}
	if !test {
		if err = e.Store.StartRun(ctx, r); err != nil {
			return model.Run{}, err
		}
	}
	stopTest := errors.New("test_sample_complete")
	err = e.Fetcher.Fetch(ctx, c, func(page collector.Page) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if r.Pages >= c.Limits.MaxPages {
			return ErrLimit
		}
		items, err := mapping.Items(page.Payload, c.Response.ItemsPath)
		if err != nil {
			return collector.Failure{Code: "invalid_json"}
		}
		if len(items) > c.Limits.MaxRecords-r.Received {
			return ErrLimit
		}
		records := []model.Record{}
		bad := []model.Rejection{}
		fetched := time.Now().UTC()
		if test && len(items) > 100 {
			items = items[:100]
		}
		for index, row := range items {
			if err := ctx.Err(); err != nil {
				return err
			}
			record, rejection := mapping.Map(row, c, fetched, r.Received+index)
			if rejection != nil {
				bad = append(bad, *rejection)
			} else {
				records = append(records, record)
			}
		}
		if !test {
			if err = e.Store.SavePage(ctx, r.ID, id, records, bad); err != nil {
				return errors.New("storage_failed")
			}
		}
		r.Pages++
		r.Attempts += page.Attempts
		r.Received += len(items)
		r.Accepted += len(records)
		r.Quarantined += len(bad)
		if test {
			return stopTest
		}
		return nil
	})
	if test && errors.Is(err, stopTest) {
		err = nil
	}
	if err == nil && r.Pages == 0 {
		err = errors.New("empty_collector_result")
	}
	r.Outcome = "success"
	if r.Quarantined > 0 {
		r.Outcome = "completed_with_errors"
	}
	if err != nil {
		r.Outcome = "failed"
		r.Error = collector.Category(err)
		if errors.Is(err, ErrLimit) {
			r.Outcome = "incomplete"
			r.Error = "collection_limit"
		} else if r.Pages > 0 {
			r.Outcome = "incomplete"
		}
		if errors.Is(err, context.Canceled) {
			r.Outcome = "interrupted"
		}
	}
	end := time.Now().UTC()
	r.EndedAt = &end
	if !test {
		finishCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if finishErr := e.Store.FinishRun(finishCtx, r, c.Schedule.IntervalSeconds); finishErr != nil {
			r.Outcome = "incomplete"
			r.Error = "run_finalization_failed"
			return r, errors.New("run_finalization_failed")
		}
	}
	return r, err
}

// Schedule uses two workers and a bounded queue. Locks and due checks are shared
// with manual runs, including when several application processes are running.
func (e *Engine) Schedule(ctx context.Context, tick time.Duration) {
	jobs := make(chan string, 10)
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case id, ok := <-jobs:
					if !ok {
						return
					}
					e.Run(ctx, id, false, true)
				}
			}
		}()
	}
	timer := time.NewTicker(tick)
	defer timer.Stop()
	defer workers.Wait()
	defer close(jobs)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			ids, err := e.Store.Due(ctx)
			if err != nil {
				continue
			}
			for _, id := range ids {
				select {
				case jobs <- id:
				default: /* due remains unchanged; retry next tick */
				}
			}
		}
	}
}
