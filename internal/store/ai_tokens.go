package store

import (
	"configbridge/internal/insights"
	"context"
	"github.com/jackc/pgx/v5"
	"time"
)

const AIReservation int64 = 40000 // bounded input plus maximum output; not billed usage

// Call-count, token reservation and requested audit either all commit or none do.
func (s Scope) ReserveMeteredAI(ctx context.Context, calls int, tokens int64, a AIAudit, operation string) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1 || (now() AT TIME ZONE 'UTC')::date::text,0))", s.LockKey("ai_tokens", "day")); e != nil {
			return e
		}
		var used int64
		if e := tx.QueryRow(ctx, "SELECT coalesce(sum(coalesce(total_tokens,reserved_tokens)),0) FROM ai_requests WHERE tenant_id=$1 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'", s.Tenant).Scan(&used); e != nil {
			return e
		}
		if calls < 1 || calls > 100 || tokens < AIReservation || used > tokens-AIReservation {
			return ErrAIBudget
		}
		tag, e := tx.Exec(ctx, `INSERT INTO ai_usage(tenant_id,day,calls)VALUES($1,(now() AT TIME ZONE 'UTC')::date,1) ON CONFLICT(tenant_id,day)DO UPDATE SET calls=ai_usage.calls+1 WHERE ai_usage.calls<$2`, s.Tenant, calls)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrAIBudget
		}
		if _, e = tx.Exec(ctx, "INSERT INTO ai_requests(tenant_id,request_id,operation,provider,model,reserved_tokens)VALUES($1,$2,$3,$4,$5,$6)", s.Tenant, a.RequestID, operation, a.Provider, a.Model, AIReservation); e != nil {
			return e
		}
		a.Outcome = "requested"
		return insertAIAudit(ctx, tx, s.Tenant, a)
	})
}

type AIRequest struct {
	ID        string    `json:"request_id"`
	Operation string    `json:"operation"`
	Provider  string    `json:"provider"`
	Model     string    `json:"model"`
	Outcome   string    `json:"outcome"`
	Reserved  int64     `json:"reserved_tokens"`
	Input     *int64    `json:"input_tokens"`
	Output    *int64    `json:"output_tokens"`
	Total     *int64    `json:"total_tokens"`
	CreatedAt time.Time `json:"created_at"`
}
type AIConsumption struct {
	Day                string      `json:"utc_day"`
	Requests           int64       `json:"requests"`
	ReportedTokens     int64       `json:"reported_tokens"`
	UnreportedReserved int64       `json:"unreported_reserved_tokens"`
	Input              int64       `json:"input_tokens"`
	Output             int64       `json:"output_tokens"`
	Recent             []AIRequest `json:"recent_requests"`
}

func (s Scope) FinishTokens(ctx context.Context, id, outcome string, u insights.Usage) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		var input, output, total any
		if u.Valid() {
			input = u.Input
			output = u.Output
			total = u.Total
		}
		tag, e := tx.Exec(ctx, "UPDATE ai_requests SET outcome=$3,input_tokens=$4,output_tokens=$5,total_tokens=$6,finished_at=now() WHERE tenant_id=$1 AND request_id=$2 AND finished_at IS NULL", s.Tenant, id, outcome, input, output, total)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return nil
	})
}
func (s Scope) AIConsumption(ctx context.Context) (out AIConsumption, err error) {
	out.Recent = []AIRequest{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT (now() AT TIME ZONE 'UTC')::date::text,count(*),coalesce(sum(total_tokens),0),coalesce(sum(reserved_tokens) FILTER(WHERE total_tokens IS NULL),0),coalesce(sum(input_tokens),0),coalesce(sum(output_tokens),0) FROM ai_requests WHERE tenant_id=$1 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, s.Tenant).Scan(&out.Day, &out.Requests, &out.ReportedTokens, &out.UnreportedReserved, &out.Input, &out.Output)
		if e != nil {
			return e
		}
		rows, e := tx.Query(ctx, "SELECT request_id,operation,provider,model,outcome,reserved_tokens,input_tokens,output_tokens,total_tokens,created_at FROM ai_requests WHERE tenant_id=$1 ORDER BY created_at DESC,request_id LIMIT 30", s.Tenant)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var a AIRequest
			if e = rows.Scan(&a.ID, &a.Operation, &a.Provider, &a.Model, &a.Outcome, &a.Reserved, &a.Input, &a.Output, &a.Total, &a.CreatedAt); e != nil {
				return e
			}
			out.Recent = append(out.Recent, a)
		}
		return rows.Err()
	})
	return
}
