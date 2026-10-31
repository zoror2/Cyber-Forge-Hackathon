package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

type AIReportTotals struct {
	Requests           int64 `json:"requests"`
	ReportedTokens     int64 `json:"reported_tokens"`
	UnreportedReserved int64 `json:"unreported_reserved_tokens"`
	Input              int64 `json:"input_tokens"`
	Output             int64 `json:"output_tokens"`
	Failed             int64 `json:"failed_requests"`
	Pending            int64 `json:"pending_requests"`
	Unknown            int64 `json:"unknown_requests"`
}
type AICustomerUsage struct {
	Customer string `json:"customer"`
	AIReportTotals
}
type AIDailyUsage struct {
	Day                string `json:"day"`
	Requests           int64  `json:"requests"`
	ReportedTokens     int64  `json:"reported_tokens"`
	UnreportedReserved int64  `json:"unreported_reserved_tokens"`
}
type AIModelUsage struct {
	Provider           string `json:"provider"`
	Model              string `json:"model"`
	Operation          string `json:"operation"`
	Requests           int64  `json:"requests"`
	ReportedTokens     int64  `json:"reported_tokens"`
	UnreportedReserved int64  `json:"unreported_reserved_tokens"`
}
type AIReportRequest struct {
	Customer   string     `json:"customer"`
	ID         string     `json:"request_id"`
	Operation  string     `json:"operation"`
	Provider   string     `json:"provider"`
	Model      string     `json:"model"`
	Outcome    string     `json:"outcome"`
	Reserved   int64      `json:"reserved_tokens"`
	Input      *int64     `json:"input_tokens"`
	Output     *int64     `json:"output_tokens"`
	Total      *int64     `json:"total_tokens"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at"`
	DurationMS *int64     `json:"duration_ms"`
}
type AIReport struct {
	From          string            `json:"from"`
	To            string            `json:"to"`
	Timezone      string            `json:"timezone"`
	Summary       AIReportTotals    `json:"summary"`
	Customers     []AICustomerUsage `json:"customers"`
	CustomerCount int64             `json:"customer_count"`
	Daily         []AIDailyUsage    `json:"daily"`
	Breakdown     []AIModelUsage    `json:"breakdown"`
	Requests      []AIReportRequest `json:"requests"`
}

func (s Scope) AIReport(ctx context.Context, from, to string, limit, offset int) (out AIReport, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL statement_timeout='5s'"); e != nil {
			return e
		}
		var raw []byte
		fn := pgx.Identifier{s.Store.namespace, "ai_consumption_report"}.Sanitize()
		if e := tx.QueryRow(ctx, "SELECT "+fn+"($1::date,$2::date,$3,$4,$5)", from, to, s.Tenant, limit, offset).Scan(&raw); e != nil {
			return e
		}
		return json.Unmarshal(raw, &out)
	})
	return
}

// OperatorAIReport is metadata-only. Its caller must authenticate the platform
// operator; customer handlers must use Scope.AIReport to retain tenant RLS.
func (s *Store) OperatorAIReport(ctx context.Context, from, to, customer string, limit, offset int) (out AIReport, err error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SET LOCAL statement_timeout='5s'"); err != nil {
		return out, err
	}
	var raw []byte
	fn := pgx.Identifier{s.namespace, "operator_ai_consumption_report"}.Sanitize()
	if err = tx.QueryRow(ctx, "SELECT "+fn+"($1::date,$2::date,$3,$4,$5)", from, to, customer, limit, offset).Scan(&raw); err != nil {
		return out, err
	}
	if err = json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	err = tx.Commit(ctx)
	return
}
