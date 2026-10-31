package store

import (
	"configbridge/internal/insights"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

// BuildSIEMSnapshot reads ONLY fixed run metadata and aggregate event fields.
// It never selects credentials, descriptions, user records or config bodies.
// Caller holds the connector lock until indexing and retrieval finish.
func (s Scope) BuildSIEMSnapshot(ctx context.Context, connector string) (out insights.Snapshot, err error) {
	out.Connector = connector
	out.Findings = []insights.Finding{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		var exists bool
		if e := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM configs WHERE tenant_id=$1 AND id=$2 AND status='live')", s.Tenant, connector).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return ErrNotFound
		}
		if e := tx.QueryRow(ctx, "SELECT gen_random_uuid()::text,now()-interval '24 hours',now()").Scan(&out.Generation, &out.WindowStart, &out.WindowEnd); e != nil {
			return e
		}
		add := func(rule, category string, n int64) {
			if n <= 0 {
				return
			}
			r, _ := insights.RuleByID(rule)
			out.Findings = append(out.Findings, insights.Finding{ID: insights.Hash(s.Tenant + "/" + connector + "/" + rule + "/" + category), Connector: connector, Generation: out.Generation, Rule: rule, Severity: r.Severity, Category: category, Count: min(n, 1_000_000_000), ObservedAt: out.WindowEnd})
		}
		rows, e := tx.Query(ctx, `SELECT outcome,error,quarantined FROM runs WHERE tenant_id=$1 AND connector=$2 AND mode='live' AND ended_at IS NOT NULL AND ended_at>=$3 AND ended_at<=$4 ORDER BY ended_at DESC,id DESC LIMIT 101`, s.Tenant, connector, out.WindowStart, out.WindowEnd)
		if e != nil {
			return e
		}
		var consecutive, rejected int64
		stopped := false
		category := "collection_failed"
		n := 0
		for rows.Next() {
			var outcome, raw string
			var bad int64
			if e = rows.Scan(&outcome, &raw, &bad); e != nil {
				rows.Close()
				return e
			}
			n++
			if n > 100 {
				out.RunSampleCapped = true
				break
			}
			rejected += bad
			if !stopped {
				if outcome == "failed" || outcome == "incomplete" || outcome == "completed_with_errors" {
					consecutive++
					if consecutive == 1 {
						category = safeCategory(raw)
						if outcome == "completed_with_errors" {
							category = "mapping_rejections"
						}
					}
				} else {
					stopped = true
				}
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if consecutive >= 3 {
			add("collection_failures", category, consecutive)
		}
		add("mapping_rejections", "mapping_rejections", rejected)
		var high, auth, kev int64
		// These are event-time windows, not ingestion-time windows. Re-fetching
		// historical events must not turn them into fresh detections.
		e = tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE payload->>'severity' IN('high','critical')),
 count(*) FILTER(WHERE payload->>'type' IN('login_failed','authentication_failure','failed_login')),
 count(*) FILTER(WHERE payload->>'type'='known_exploited_vulnerability')
 FROM events WHERE tenant_id=$1 AND source=$2 AND (payload->>'timestamp')::timestamptz >=$3 AND (payload->>'timestamp')::timestamptz <=$4`, s.Tenant, connector, out.WindowStart, out.WindowEnd).Scan(&high, &auth, &kev)
		if e != nil {
			return e
		}
		add("high_severity_events", "source_high_severity", high)
		if auth >= 5 {
			add("authentication_failures", "authentication_failure", auth)
		}
		add("kev_catalog_entries", "public_kev_catalog", kev)
		_, e = tx.Exec(ctx, `INSERT INTO siem_snapshots(tenant_id,connector,generation,window_start,window_end,run_sample_capped)VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,connector)DO UPDATE SET generation=excluded.generation,window_start=excluded.window_start,window_end=excluded.window_end,run_sample_capped=excluded.run_sample_capped`, s.Tenant, connector, out.Generation, out.WindowStart, out.WindowEnd, out.RunSampleCapped)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "DELETE FROM siem_findings WHERE tenant_id=$1 AND connector=$2", s.Tenant, connector); e != nil {
			return e
		}
		for _, f := range out.Findings {
			if _, e = tx.Exec(ctx, `INSERT INTO siem_findings(tenant_id,connector,id,generation,rule,severity,category,count,observed_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, s.Tenant, connector, f.ID, f.Generation, f.Rule, f.Severity, f.Category, f.Count, f.ObservedAt); e != nil {
				return e
			}
		}
		return nil
	})
	return
}
func (s Scope) SIEMSnapshot(ctx context.Context, connector string) (out insights.Snapshot, err error) {
	out.Connector = connector
	out.Findings = []insights.Finding{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx, "SELECT generation,window_start,window_end,run_sample_capped FROM siem_snapshots WHERE tenant_id=$1 AND connector=$2", s.Tenant, connector).Scan(&out.Generation, &out.WindowStart, &out.WindowEnd, &out.RunSampleCapped)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		rows, e := tx.Query(ctx, "SELECT id,connector,generation,rule,severity,category,count,observed_at FROM siem_findings WHERE tenant_id=$1 AND connector=$2 AND generation=$3 ORDER BY rule,category LIMIT 20", s.Tenant, connector, out.Generation)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var f insights.Finding
			if e = rows.Scan(&f.ID, &f.Connector, &f.Generation, &f.Rule, &f.Severity, &f.Category, &f.Count, &f.ObservedAt); e != nil {
				return e
			}
			out.Findings = append(out.Findings, f)
		}
		return rows.Err()
	})
	return
}

// ResolveSIEM refuses stale, fabricated, duplicate and cross-tenant search hits.
// Search is an index of candidate IDs, never the authority for LLM evidence.
func (s Scope) ResolveSIEM(ctx context.Context, connector, generation string, ids []string, topic string) ([]insights.Finding, error) {
	snap, e := s.SIEMSnapshot(ctx, connector)
	if e != nil {
		return nil, e
	}
	if snap.Generation != generation || time.Since(snap.WindowEnd) > time.Minute {
		return nil, insights.ErrEvidence
	}
	known := map[string]insights.Finding{}
	for _, f := range snap.Findings {
		r, ok := insights.RuleByID(f.Rule)
		if ok && r.Topic == topic {
			known[f.ID] = f
		}
	}
	out := []insights.Finding{}
	for _, id := range ids {
		f, ok := known[id]
		if !ok {
			return nil, insights.ErrEvidence
		}
		delete(known, id)
		out = append(out, f)
	}
	// Missing hits would let an incomplete/stale index hide known findings.
	if len(known) != 0 {
		return nil, insights.ErrEvidence
	}
	return out, nil
}
