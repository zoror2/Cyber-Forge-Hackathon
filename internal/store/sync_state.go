package store

import (
	"configbridge/pkg/incremental"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

type SyncState struct {
	Connector   string                  `json:"connector"`
	LastSuccess *time.Time              `json:"last_success"`
	NextDue     *time.Time              `json:"next_due"`
	Watermark   *incremental.Checkpoint `json:"watermark"`
}

func (s Scope) SyncState(ctx context.Context, id string) (out SyncState, err error) {
	out.Connector = id
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		var raw []byte
		e := tx.QueryRow(ctx, "SELECT last_success,next_due,watermark FROM sync_state WHERE tenant_id=$1 AND connector=$2", s.Tenant, id).Scan(&out.LastSuccess, &out.NextDue, &raw)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		if len(raw) > 0 && json.Unmarshal(raw, &out.Watermark) != nil {
			return incremental.ErrState
		}
		return nil
	})
	return
}
