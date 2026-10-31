// Package store owns PostgreSQL persistence and cross-process connector locks.
package store

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/config"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/model"
)

//go:embed migrations/001_initial.sql
var migration string
var ErrNotFound = errors.New("not_found")
var ErrBusy = errors.New("connector_busy")

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, dsn string) (*Store, error) {
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	pc.MaxConns = 16
	p, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, errors.New("database unavailable")
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, errors.New("database unavailable")
	}
	return &Store{p}, nil
}
func (s *Store) Migrate(ctx context.Context) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(73423001)"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); e != nil {
		return e
	}
	var exists bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=1)").Scan(&exists); e != nil {
		return e
	}
	if !exists {
		if _, e = tx.Exec(ctx, migration); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES(1)"); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}

type SavedConfig struct {
	Config   config.Config `json:"config"`
	Revision int           `json:"revision"`
	Status   string        `json:"status"`
	Hash     string        `json:"hash"`
}

func (s *Store) SaveConfig(ctx context.Context, c config.Config) (SavedConfig, error) {
	if len(c.Validate()) > 0 {
		return SavedConfig{}, errors.New("invalid_config")
	}
	body, e := json.Marshal(c)
	if e != nil {
		return SavedConfig{}, e
	}
	hash := sha256.Sum256(body)
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return SavedConfig{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "config-version:"+c.ID); e != nil {
		return SavedConfig{}, e
	}
	var v int
	if e = tx.QueryRow(ctx, "SELECT COALESCE(MAX(version),0)+1 FROM configs WHERE id=$1", c.ID).Scan(&v); e != nil {
		return SavedConfig{}, e
	}
	h := hex.EncodeToString(hash[:])
	if _, e = tx.Exec(ctx, "INSERT INTO configs(id,version,status,body,config_hash) VALUES($1,$2,'draft',$3,$4)", c.ID, v, body, h); e != nil {
		return SavedConfig{}, e
	}
	return SavedConfig{c, v, "draft", h}, tx.Commit(ctx)
}
func (s *Store) Config(ctx context.Context, id string, live bool) (SavedConfig, error) {
	q := "SELECT body,version,status,config_hash FROM configs WHERE id=$1"
	if live {
		q += " AND status='live'"
	}
	q += " ORDER BY version DESC LIMIT 1"
	var v SavedConfig
	var b []byte
	e := s.Pool.QueryRow(ctx, q, id).Scan(&b, &v.Revision, &v.Status, &v.Hash)
	if errors.Is(e, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	if e != nil {
		return v, e
	}
	e = json.Unmarshal(b, &v.Config)
	return v, e
}
func (s *Store) Activate(ctx context.Context, id string, version int) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var locked bool
	if e = tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))", "connector:"+id).Scan(&locked); e != nil {
		return e
	}
	if !locked {
		return ErrBusy
	}
	var b []byte
	if e = tx.QueryRow(ctx, "SELECT body FROM configs WHERE id=$1 AND version=$2", id, version).Scan(&b); errors.Is(e, pgx.ErrNoRows) {
		return ErrNotFound
	} else if e != nil {
		return e
	}
	var c config.Config
	if json.Unmarshal(b, &c) != nil || len(c.Validate()) > 0 {
		return errors.New("invalid_config")
	}
	if _, e = tx.Exec(ctx, "UPDATE configs SET status='approved' WHERE id=$1 AND status='live'", id); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE configs SET status='live' WHERE id=$1 AND version=$2", id, version); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO sync_state(connector,next_due) VALUES($1,now()) ON CONFLICT(connector) DO UPDATE SET next_due=now()", id); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// Lock keeps one physical connection checked out until release. A lost connection
// cancels work; closing it on uncertain unlock prevents a lock leaking into the pool.
func (s *Store) Lock(ctx context.Context, id string) (context.Context, func(), error) {
	conn, e := s.Pool.Acquire(ctx)
	if e != nil {
		return ctx, nil, e
	}
	var locked bool
	e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", "connector:"+id).Scan(&locked)
	if e != nil || !locked {
		conn.Release()
		if e != nil {
			return ctx, nil, e
		}
		return ctx, nil, ErrBusy
	}
	leaseCtx, cancelLease := context.WithCancel(ctx)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-leaseCtx.Done():
				return
			case <-tick.C:
				check, cancel := context.WithTimeout(leaseCtx, time.Second)
				err := conn.Ping(check)
				cancel()
				if err != nil {
					cancelLease()
					return
				}
			}
		}
	}()
	return leaseCtx, func() {
		close(stop)
		<-done
		cancelLease()
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		err := conn.QueryRow(cleanup, "SELECT pg_advisory_unlock(hashtextextended($1,0))", "connector:"+id).Scan(&unlocked)
		if err != nil || !unlocked {
			conn.Conn().Close(cleanup)
		}
		conn.Release()
	}, nil
}

// Recover only interrupts abandoned runs after acquiring their connector lock;
// another healthy process holding the lock is left alone.
func (s *Store) Recover(ctx context.Context) error {
	rows, err := s.Pool.Query(ctx, "SELECT DISTINCT connector FROM runs WHERE outcome='running'")
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		_, release, err := s.Lock(ctx, id)
		if errors.Is(err, ErrBusy) {
			continue
		}
		if err != nil {
			return err
		}
		_, err = s.Pool.Exec(ctx, "UPDATE runs SET outcome='interrupted',ended_at=now(),error='interrupted' WHERE connector=$1 AND outcome='running'", id)
		release()
		if err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) StartRun(ctx context.Context, r model.Run) error {
	_, e := s.Pool.Exec(ctx, `UPDATE runs SET outcome='interrupted',ended_at=now(),error='interrupted' WHERE connector=$1 AND outcome='running'`, r.Connector)
	if e != nil {
		return e
	}
	_, e = s.Pool.Exec(ctx, `INSERT INTO runs(id,connector,config_version,config_hash,mode,started_at,outcome) VALUES($1,$2,$3,$4,$5,$6,'running')`, r.ID, r.Connector, r.ConfigVersion, r.ConfigHash, r.Mode, r.StartedAt)
	return e
}

var tables = map[string]string{"user": "users", "device": "devices", "event": "events"}

func (s *Store) SavePage(ctx context.Context, runID, source string, records []model.Record, bad []model.Rejection) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	// Fences an abandoned worker if a replacement run has already interrupted it.
	var active bool
	if e = tx.QueryRow(ctx, "SELECT outcome='running' FROM runs WHERE id=$1 FOR UPDATE", runID).Scan(&active); e != nil {
		return e
	}
	if !active {
		return errors.New("run_interrupted")
	}
	for _, r := range records {
		table, ok := tables[r.Entity]
		if !ok {
			return errors.New("unknown entity")
		}
		_, e = tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s(source,external_id,payload,fetched_at,run_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT(source,external_id) DO UPDATE SET payload=excluded.payload,fetched_at=excluded.fetched_at,run_id=excluded.run_id`, table), r.Source, r.ID, []byte(r.Payload), r.FetchedAt, runID)
		if e != nil {
			return e
		}
	}
	for _, q := range bad {
		if _, e = tx.Exec(ctx, "INSERT INTO quarantine(run_id,source,record_index,field,reason) VALUES($1,$2,$3,$4,$5)", runID, source, q.Index, q.Field, q.Reason); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) FinishRun(ctx context.Context, r model.Run, interval int) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, `UPDATE runs SET ended_at=$2,outcome=$3,pages=$4,attempts=$5,received=$6,accepted=$7,quarantined=$8,error=$9 WHERE id=$1 AND outcome='running'`, r.ID, r.EndedAt, r.Outcome, r.Pages, r.Attempts, r.Received, r.Accepted, r.Quarantined, r.Error)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("run_interrupted")
	}
	if interval < 1 {
		interval = 60
	}
	_, e = tx.Exec(ctx, `INSERT INTO sync_state(connector,last_success,next_due) VALUES($1,CASE WHEN $2 THEN $3::timestamptz ELSE NULL END,now()+make_interval(secs=>$4)) ON CONFLICT(connector) DO UPDATE SET last_success=CASE WHEN $2 THEN $3::timestamptz ELSE sync_state.last_success END,next_due=now()+make_interval(secs=>$4)`, r.Connector, r.Outcome == "success", r.EndedAt, interval)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) Due(ctx context.Context) ([]string, error) {
	rows, e := s.Pool.Query(ctx, `SELECT c.id FROM configs c JOIN sync_state s ON s.connector=c.id WHERE c.status='live' AND c.body->'schedule'->>'enabled'='true' AND s.next_due<=now() ORDER BY s.next_due LIMIT 100`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (s *Store) IsDue(ctx context.Context, id string) (bool, error) {
	var due bool
	e := s.Pool.QueryRow(ctx, "SELECT next_due<=now() FROM sync_state WHERE connector=$1", id).Scan(&due)
	return due, e
}
func (s *Store) Runs(ctx context.Context, id string, limit, offset int) ([]model.Run, error) {
	rows, e := s.Pool.Query(ctx, `SELECT id,connector,config_version,config_hash,mode,started_at,ended_at,outcome,pages,attempts,received,accepted,quarantined,error FROM runs WHERE ($1='' OR connector=$1) ORDER BY started_at DESC,id LIMIT $2 OFFSET $3`, id, limit, offset)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Run{}
	for rows.Next() {
		var r model.Run
		if e = rows.Scan(&r.ID, &r.Connector, &r.ConfigVersion, &r.ConfigHash, &r.Mode, &r.StartedAt, &r.EndedAt, &r.Outcome, &r.Pages, &r.Attempts, &r.Received, &r.Accepted, &r.Quarantined, &r.Error); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) Records(ctx context.Context, entity, source string, limit, offset int) ([]json.RawMessage, error) {
	table, ok := tables[entity]
	if !ok {
		return nil, ErrNotFound
	}
	rows, e := s.Pool.Query(ctx, "SELECT payload FROM "+table+" WHERE ($1='' OR source=$1) ORDER BY source,external_id LIMIT $2 OFFSET $3", source, limit, offset)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var p []byte
		if e = rows.Scan(&p); e != nil {
			return nil, e
		}
		out = append(out, json.RawMessage(p))
	}
	return out, rows.Err()
}
func (s *Store) Quarantine(ctx context.Context, id string, limit, offset int) ([]map[string]any, error) {
	rows, e := s.Pool.Query(ctx, "SELECT run_id,source,record_index,field,reason FROM quarantine WHERE ($1='' OR source=$1) ORDER BY id DESC LIMIT $2 OFFSET $3", id, limit, offset)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var run, source, field, reason string
		var index int
		if e = rows.Scan(&run, &source, &index, &field, &reason); e != nil {
			return nil, e
		}
		out = append(out, map[string]any{"run_id": run, "source": source, "record_index": index, "field": field, "reason": reason})
	}
	return out, rows.Err()
}

type Health struct {
	Connector   string     `json:"connector"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	LastRun     *time.Time `json:"last_run"`
	LastSuccess *time.Time `json:"last_success"`
	Accepted    int        `json:"accepted"`
	Error       string     `json:"error"`
}

func (s *Store) Health(ctx context.Context, limit, offset int) ([]Health, error) {
	rows, e := s.Pool.Query(ctx, `SELECT c.id,c.body->>'name',COALESCE(r.outcome,'idle'),r.started_at,s.last_success,COALESCE(r.accepted,0),COALESCE(r.error,'') FROM configs c LEFT JOIN sync_state s ON s.connector=c.id LEFT JOIN LATERAL (SELECT outcome,started_at,accepted,error FROM runs WHERE connector=c.id ORDER BY started_at DESC LIMIT 1) r ON true WHERE c.status='live' ORDER BY c.id LIMIT $1 OFFSET $2`, limit, offset)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Health{}
	for rows.Next() {
		var h Health
		if e = rows.Scan(&h.Connector, &h.Name, &h.Status, &h.LastRun, &h.LastSuccess, &h.Accepted, &h.Error); e != nil {
			return nil, e
		}
		switch h.Status {
		case "success":
			h.Status = "healthy"
		case "completed_with_errors", "incomplete":
			h.Status = "degraded"
		case "interrupted":
			h.Status = "failed"
		}
		if h.Error == "rate_limited" {
			h.Status = "rate_limited"
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
