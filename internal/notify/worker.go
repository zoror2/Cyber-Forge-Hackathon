package notify

import (
	"configbridge/internal/store"
	"context"
	"log/slog"
	"sync"
	"time"
)

type Sender interface {
	Send(context.Context, string, store.Alert) error
}
type Worker struct {
	Store  *store.Store
	Sender Sender
	Routes map[string]string
	// Optional tenant-scoped account-admin lookup; explicit routes take precedence.
	AccountRecipient func(context.Context, string) (string, error)
}

func (w *Worker) Recipient(ctx context.Context, tenant string) (string, error) {
	if to, ok := w.Routes[tenant]; ok {
		return to, nil
	}
	if w.AccountRecipient != nil {
		to, err := w.AccountRecipient(ctx, tenant)
		if err != nil {
			return "", err
		}
		if ValidEmail(to) {
			return to, nil
		}
	}
	return "", nil
}

func (w *Worker) Process(ctx context.Context, j store.AlertJob) error {
	scope := w.Store.ForTenant(j.Tenant)
	lease, unlock, err := scope.Lock(ctx, j.Connector)
	if err != nil {
		return err
	}
	defer unlock()
	to, err := w.Recipient(lease, j.Tenant)
	if err != nil || to == "" {
		return err
	}
	a, err := scope.ClaimAlert(lease, j.ID)
	if err != nil || a.ID == "" {
		return err
	}
	sent := w.Sender.Send(lease, to, a) == nil
	finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = scope.FinishAlert(finish, a, sent); err != nil {
		return err
	}
	if !sent {
		slog.Warn("connection alert delivery deferred", "tenant_id", j.Tenant, "alert_id", j.ID, "category", "smtp_unavailable")
	}
	return nil
}
func (w *Worker) Run(ctx context.Context, tick time.Duration) {
	jobs := make(chan store.AlertJob, 20)
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
					w.Process(ctx, j)
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
			due, err := w.Store.DueAlerts(ctx)
			if err != nil {
				continue
			}
			for _, j := range due {
				select {
				case jobs <- j:
				default:
				}
			}
		}
	}
}
