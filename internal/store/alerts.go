package store

import (
	"configbridge/pkg/config"
	"configbridge/pkg/model"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

type Alert struct {
	TenantID      string     `json:"tenant_id"`
	ID            string     `json:"id"`
	Connector     string     `json:"connector"`
	RunID         string     `json:"run_id"`
	Episode       int64      `json:"episode"`
	FailureCount  int        `json:"failure_count"`
	Error         string     `json:"error"`
	Outcome       string     `json:"outcome"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	CreatedAt     time.Time  `json:"created_at"`
	SentAt        *time.Time `json:"sent_at"`
	DeliveryError string     `json:"delivery_error"`
	Token         string     `json:"-"`
}

func safeCategory(s string) string {
	switch s {
	case "auth_failed", "credential_missing", "credential_incomplete", "credential_binding_mismatch", "destination_denied", "response_too_large", "collection_limit", "timeout", "rate_limited", "vendor_http_failed", "collection_failed", "storage_failed", "incremental_filter_not_respected":
		return s
	}
	return "collection_failed"
}
func (s Scope) queueAlert(ctx context.Context, tx pgx.Tx, r model.Run) error {
	if r.Mode != "live" || r.Outcome == "interrupted" {
		return nil
	}
	var raw []byte
	if err := tx.QueryRow(ctx, "SELECT body FROM configs WHERE tenant_id=$1 AND id=$2 AND version=$3", s.Tenant, r.Connector, r.ConfigVersion).Scan(&raw); err != nil {
		return err
	}
	var c config.Config
	if json.Unmarshal(raw, &c) != nil {
		return errors.New("invalid_notification_config")
	}
	n := c.Notifications
	if n == nil || !n.Enabled || r.Outcome == "success" {
		return s.resetAlerts(ctx, tx, r.Connector)
	}
	if r.Outcome != "failed" && r.Outcome != "incomplete" && r.Outcome != "completed_with_errors" {
		return nil
	}
	var streak int
	var episode, notified int64
	var eligible bool
	err := tx.QueryRow(ctx, `INSERT INTO alert_state(tenant_id,connector,failure_streak,episode)VALUES($1,$2,1,1)
 ON CONFLICT(tenant_id,connector) DO UPDATE SET failure_streak=LEAST(alert_state.failure_streak+1,1000000),episode=CASE WHEN alert_state.failure_streak=0 THEN alert_state.episode+1 ELSE alert_state.episode END
 RETURNING failure_streak,episode,notified_episode,last_queued_at IS NULL OR last_queued_at<=now()-make_interval(secs=>$3)`, s.Tenant, r.Connector, n.CooldownSeconds).Scan(&streak, &episode, &notified, &eligible)
	if err != nil {
		return err
	}
	if streak < n.FailureThreshold || episode == notified || !eligible {
		return nil
	}
	category := safeCategory(r.Error)
	if r.Outcome == "completed_with_errors" {
		category = "mapping_rejections"
	}
	if _, err = tx.Exec(ctx, `INSERT INTO alert_outbox(tenant_id,connector,run_id,episode,failure_count,error_category,outcome)VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,connector,episode) DO NOTHING`, s.Tenant, r.Connector, r.ID, episode, streak, category, r.Outcome); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE alert_state SET notified_episode=$3,last_queued_at=now() WHERE tenant_id=$1 AND connector=$2", s.Tenant, r.Connector, episode)
	return err
}
func (s Scope) resetAlerts(ctx context.Context, tx pgx.Tx, connector string) error {
	if _, err := tx.Exec(ctx, "UPDATE alert_state SET failure_streak=0 WHERE tenant_id=$1 AND connector=$2", s.Tenant, connector); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "UPDATE alert_outbox SET status='cancelled',lease_token=NULL,lease_until=NULL WHERE tenant_id=$1 AND connector=$2 AND status IN('pending','sending')", s.Tenant, connector)
	return err
}

type AlertJob struct{ Tenant, ID, Connector string }

func (s *Store) DueAlerts(ctx context.Context) (out []AlertJob, err error) {
	rows, err := s.Pool.Query(ctx, "SELECT tenant_id,id,connector FROM due_alerts()")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var j AlertJob
		if err = rows.Scan(&j.Tenant, &j.ID, &j.Connector); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Caller holds the connector session lock, serializing recovery/config changes
// with delivery. The lease/token also fence workers after a lost lock session.
func (s Scope) ClaimAlert(ctx context.Context, id string) (out Alert, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		var connector string
		var episode int64
		var attempts int
		e := tx.QueryRow(ctx, `SELECT connector,episode,attempts FROM alert_outbox WHERE tenant_id=$1 AND id=$2 AND ((status='pending' AND next_attempt_at<=now()) OR (status='sending' AND lease_until<=now())) FOR UPDATE`, s.Tenant, id).Scan(&connector, &episode, &attempts)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		var relevant bool
		e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM configs c JOIN alert_state a ON a.tenant_id=c.tenant_id AND a.connector=c.id WHERE c.tenant_id=$1 AND c.id=$2 AND c.status='live' AND c.body#>>'{notifications,enabled}'='true' AND a.failure_streak>0 AND a.episode=$3)`, s.Tenant, connector, episode).Scan(&relevant)
		if e != nil {
			return e
		}
		if !relevant || attempts >= 5 {
			status := "cancelled"
			if relevant {
				status = "abandoned"
			}
			_, e = tx.Exec(ctx, "UPDATE alert_outbox SET status=$3,lease_token=NULL,lease_until=NULL WHERE tenant_id=$1 AND id=$2", s.Tenant, id, status)
			return e
		}
		e = tx.QueryRow(ctx, `UPDATE alert_outbox SET status='sending',attempts=attempts+1,lease_until=now()+interval '2 minutes',lease_token=gen_random_uuid()::text WHERE tenant_id=$1 AND id=$2 RETURNING tenant_id,id,connector,run_id,episode,failure_count,error_category,outcome,status,attempts,created_at,sent_at,last_delivery_error,lease_token`, s.Tenant, id).Scan(&out.TenantID, &out.ID, &out.Connector, &out.RunID, &out.Episode, &out.FailureCount, &out.Error, &out.Outcome, &out.Status, &out.Attempts, &out.CreatedAt, &out.SentAt, &out.DeliveryError, &out.Token)
		return e
	})
	return
}
func (s Scope) FinishAlert(ctx context.Context, a Alert, sent bool) error {
	if a.Attempts < 1 || a.Token == "" {
		return ErrNotFound
	}
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		status, category := "pending", "smtp_unavailable"
		if sent {
			status = "sent"
			category = ""
		} else if a.Attempts >= 5 {
			status = "abandoned"
		}
		seconds := min(60*(1<<min(a.Attempts-1, 4)), 900)
		tag, e := tx.Exec(ctx, `UPDATE alert_outbox SET status=$4,sent_at=CASE WHEN $5 THEN now() ELSE NULL END,last_delivery_error=$6,next_attempt_at=now()+make_interval(secs=>$7),lease_until=NULL,lease_token=NULL WHERE tenant_id=$1 AND id=$2 AND lease_token=$3 AND status='sending'`, s.Tenant, a.ID, a.Token, status, sent, category, seconds)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return nil
	})
}
func (s Scope) Alerts(ctx context.Context, connector string, limit, offset int) (out []Alert, err error) {
	out = []Alert{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT tenant_id,id,connector,run_id,episode,failure_count,error_category,outcome,status,attempts,created_at,sent_at,last_delivery_error FROM alert_outbox WHERE tenant_id=$1 AND ($2='' OR connector=$2) ORDER BY created_at DESC,id LIMIT $3 OFFSET $4`, s.Tenant, connector, limit, offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var a Alert
			if e = rows.Scan(&a.TenantID, &a.ID, &a.Connector, &a.RunID, &a.Episode, &a.FailureCount, &a.Error, &a.Outcome, &a.Status, &a.Attempts, &a.CreatedAt, &a.SentAt, &a.DeliveryError); e != nil {
				return e
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return
}
