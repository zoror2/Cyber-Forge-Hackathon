package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

var ErrAIBudget = errors.New("ai_daily_limit_reached")

type AIAudit struct {
	RequestID     string    `json:"request_id"`
	Actor         string    `json:"actor"`
	SourceID      string    `json:"source_id"`
	SourceHash    string    `json:"source_hash"`
	Provider      string    `json:"provider"`
	Model         string    `json:"model"`
	PromptVersion string    `json:"prompt_version"`
	Outcome       string    `json:"outcome"`
	OutputHash    string    `json:"output_hash"`
	CreatedAt     time.Time `json:"created_at"`
}

func insertAIAudit(ctx context.Context, tx pgx.Tx, tenant string, a AIAudit) error {
	_, err := tx.Exec(ctx, `INSERT INTO ai_audit(tenant_id,request_id,actor,source_id,source_hash,provider,model,prompt_version,outcome,output_hash)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, tenant, a.RequestID, a.Actor, a.SourceID, a.SourceHash, a.Provider, a.Model, a.PromptVersion, a.Outcome, a.OutputHash)
	return err
}

// Reserve before calling the provider; failed/cancelled calls count too. The
// database budget is shared by replicas and survives process restarts.
func (s Scope) ReserveAI(ctx context.Context, limit int, a AIAudit) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO ai_usage(tenant_id,day,calls)VALUES($1,(now() AT TIME ZONE 'UTC')::date,1)
   ON CONFLICT(tenant_id,day) DO UPDATE SET calls=ai_usage.calls+1 WHERE ai_usage.calls<$2`, s.Tenant, limit)
		if err != nil {
			return err
		}
		if limit < 1 || tag.RowsAffected() != 1 {
			return ErrAIBudget
		}
		a.Outcome = "requested"
		return insertAIAudit(ctx, tx, s.Tenant, a)
	})
}
func (s Scope) RecordAI(ctx context.Context, a AIAudit) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error { return insertAIAudit(ctx, tx, s.Tenant, a) })
}
func (s Scope) AIAudits(ctx context.Context, limit, offset int) (out []AIAudit, err error) {
	out = []AIAudit{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT request_id,actor,source_id,source_hash,provider,model,prompt_version,outcome,output_hash,created_at FROM ai_audit WHERE tenant_id=$1 ORDER BY id DESC LIMIT $2 OFFSET $3`, s.Tenant, limit, offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var a AIAudit
			if e = rows.Scan(&a.RequestID, &a.Actor, &a.SourceID, &a.SourceHash, &a.Provider, &a.Model, &a.PromptVersion, &a.Outcome, &a.OutputHash, &a.CreatedAt); e != nil {
				return e
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return
}
