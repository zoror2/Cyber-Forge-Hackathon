// Package store enforces tenant scope through both parameterized queries and
// PostgreSQL row-level security. Every customer-data operation uses a Scope.
package store

import (
	"configbridge/pkg/config"
	"configbridge/pkg/incremental"
	"configbridge/pkg/model"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"time"
)

//go:embed migrations/001_initial.sql
var migration string

//go:embed migrations/002_exposure.sql
var migrationExposure string

//go:embed migrations/003_ai_drafts.sql
var migrationAI string

//go:embed migrations/004_incremental.sql
var migrationIncremental string

//go:embed migrations/005_notifications.sql
var migrationNotifications string

//go:embed migrations/006_ocsf.sql
var migrationOCSF string

//go:embed migrations/007_prd_views.sql
var migrationPRDViews string

//go:embed migrations/008_scale.sql
var migrationScale string

//go:embed migrations/009_exposure_ocsf.sql
var migrationExposureOCSF string

// migrations run in order, once each, inside the migration transaction. Each
// lists the tables it creates so they get forced row-level security.
// 2-5 were applied first on main; OCSF (6) retires the PRD-era tables after them.
var migrations = []struct {
	version int
	sql     string
	tables  []string
}{
	{1, migration, []string{"tenants", "api_keys", "configs", "credentials_meta", "credentials_values", "runs", "users", "devices", "events", "quarantine", "sync_state"}},
	{2, migrationExposure, nil},
	{3, migrationAI, []string{"ai_usage", "ai_audit"}},
	{4, migrationIncremental, nil},
	{5, migrationNotifications, []string{"alert_state", "alert_outbox"}},
	{6, migrationOCSF, []string{"ocsf_records"}},
	{7, migrationPRDViews, nil},
	{8, migrationScale, nil},
	{9, migrationExposureOCSF, nil},
}
var ErrNotFound = errors.New("not_found")
var ErrBusy = errors.New("connector_busy")

type Store struct {
	Pool      *pgxpool.Pool
	namespace string
}
type Scope struct {
	Store  *Store
	Tenant string
}

func (s *Store) ForTenant(id string) Scope { return Scope{s, id} }
func Open(ctx context.Context, dsn string) (*Store, error) {
	pc, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		return nil, errors.New("invalid database configuration")
	}
	pc.MaxConns = 20
	p, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		return nil, errors.New("database unavailable")
	}
	var unsafe bool
	e = p.QueryRow(ctx, `SELECT r.rolsuper OR r.rolbypassrls OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relkind='r' AND pg_has_role(current_user,c.relowner,'MEMBER')) FROM pg_roles r WHERE r.rolname=current_user`).Scan(&unsafe)
	if e != nil || unsafe {
		p.Close()
		return nil, errors.New("runtime database role must not own tables, be superuser, or bypass RLS")
	}
	var schema string
	if e = p.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); e != nil || schema == "" {
		p.Close()
		return nil, errors.New("runtime database schema unavailable")
	}
	return &Store{Pool: p, namespace: schema}, nil
}

// LockKey includes the application schema because PostgreSQL advisory locks
// otherwise collide across independent schemas within the same database.
func (s Scope) LockKey(purpose, id string) string {
	return fmt.Sprintf("configbridge:%q:%q:%q:%q", s.Store.namespace, purpose, s.Tenant, id)
}
func Migrate(ctx context.Context, dsn, appRole string) error {
	p, e := pgxpool.New(ctx, dsn)
	if e != nil {
		return errors.New("migration database unavailable")
	}
	defer p.Close()
	tx, e := p.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(73423001)"); e != nil {
		return e
	}
	var schema, owner string
	if e = tx.QueryRow(ctx, "SELECT current_schema(),current_user").Scan(&schema, &owner); e != nil {
		return e
	}
	if owner == appRole {
		return errors.New("migration role must differ from runtime role")
	}
	if _, e = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version integer PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now())`); e != nil {
		return e
	}
	for _, m := range migrations {
		var exists bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", m.version).Scan(&exists); e != nil {
			return e
		}
		if exists {
			continue
		}
		policies := ""
		for _, table := range m.tables {
			quoted := pgx.Identifier{schema, table}.Sanitize()
			policies += fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY; ALTER TABLE %s FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_isolation ON %s USING (tenant_id=current_setting('app.tenant_id',true) OR current_user=%s) WITH CHECK (tenant_id=current_setting('app.tenant_id',true) OR current_user=%s);", quoted, quoted, quoted, literal(owner), literal(owner))
		}
		sql := strings.ReplaceAll(m.sql, "__SCHEMA__", pgx.Identifier{schema}.Sanitize())
		sql = strings.Replace(sql, "__RLS_POLICIES__", policies, 1)
		if _, e = tx.Exec(ctx, sql); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO schema_migrations(version)VALUES($1)", m.version); e != nil {
			return e
		}
	}
	role := pgx.Identifier{appRole}.Sanitize()
	sch := pgx.Identifier{schema}.Sanitize()
	if _, e = tx.Exec(ctx, "GRANT SELECT,INSERT ON "+sch+".ai_audit TO "+role+"; GRANT SELECT,INSERT,UPDATE ON "+sch+".ai_usage TO "+role); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "GRANT SELECT,INSERT,UPDATE ON "+sch+".alert_state,"+sch+".alert_outbox TO "+role); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "GRANT USAGE ON SCHEMA "+sch+" TO "+role); e != nil {
		return e
	}
	for _, table := range []string{"configs", "credentials_meta", "credentials_values", "runs", "ocsf_records", "quarantine", "sync_state"} {
		if _, e = tx.Exec(ctx, "GRANT SELECT,INSERT,UPDATE,DELETE ON "+pgx.Identifier{schema, table}.Sanitize()+" TO "+role); e != nil {
			return e
		}
	}
	for _, table := range append([]string{"tenants"}, PRDViews...) {
		if _, e = tx.Exec(ctx, "GRANT SELECT ON "+pgx.Identifier{schema, table}.Sanitize()+" TO "+role); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, "GRANT SELECT ON "+sch+".vendor_aliases TO "+role); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "GRANT USAGE ON ALL SEQUENCES IN SCHEMA "+sch+" TO "+role); e != nil {
		return e
	}
	for _, fn := range []string{"authenticate_api_key(bytea)", "authenticate_api_key_identity(bytea)", "due_connectors()", "running_connectors()", "due_alerts()"} {
		if _, e = tx.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+sch+"."+fn+" TO "+role); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
func literal(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }

// Bootstrap is a provisioning operation on the migration connection. No HTTP
// endpoint can mint API keys, choose tenants, or read their hashes.
func Bootstrap(ctx context.Context, dsn, tenant, apiKey, kmsKey string) error {
	if !config.ValidID(tenant) || len(apiKey) < 32 {
		return errors.New("invalid tenant or bootstrap API key")
	}
	p, e := pgxpool.New(ctx, dsn)
	if e != nil {
		return e
	}
	defer p.Close()
	tx, e := p.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "INSERT INTO tenants(tenant_id,kms_key_id)VALUES($1,$2) ON CONFLICT(tenant_id) DO NOTHING", tenant, kmsKey); e != nil {
		return e
	}
	var storedKey string
	if e = tx.QueryRow(ctx, "SELECT kms_key_id FROM tenants WHERE tenant_id=$1", tenant).Scan(&storedKey); e != nil {
		return e
	}
	if storedKey != kmsKey {
		return errors.New("tenant KMS binding is immutable during bootstrap")
	}
	hash := sha256.Sum256([]byte(apiKey))
	_, e = tx.Exec(ctx, "INSERT INTO api_keys(key_hash,tenant_id)VALUES($1,$2) ON CONFLICT(key_hash) DO NOTHING", hash[:], tenant)
	if e != nil {
		return e
	}
	var keyTenant string
	if e = tx.QueryRow(ctx, "SELECT tenant_id FROM api_keys WHERE key_hash=$1", hash[:]).Scan(&keyTenant); e != nil {
		return e
	}
	if keyTenant != tenant {
		return errors.New("API key already belongs to another tenant")
	}
	return tx.Commit(ctx)
}
func (s *Store) Authenticate(ctx context.Context, key string) (string, error) {
	caller, err := s.AuthenticateCaller(ctx, key)
	return caller.Tenant, err
}

type Caller struct {
	Tenant string
	Actor  string
}

func (s *Store) AuthenticateCaller(ctx context.Context, key string) (Caller, error) {
	hash := sha256.Sum256([]byte(key))
	var tenant, principal string
	var stored []byte
	e := s.Pool.QueryRow(ctx, "SELECT tenant_id,key_hash,principal_id FROM authenticate_api_key_identity($1)", hash[:]).Scan(&tenant, &stored, &principal)
	if e != nil || !config.ValidID(tenant) {
		return Caller{}, ErrNotFound
	}
	// The narrow security-definer lookup returns no unhashed key or customer data.
	if e != nil || subtle.ConstantTimeCompare(stored, hash[:]) != 1 {
		return Caller{}, ErrNotFound
	}
	return Caller{Tenant: tenant, Actor: "api_key:" + principal}, nil
}
func (s Scope) WithTx(ctx context.Context, fn func(pgx.Tx) error) error {
	if !config.ValidID(s.Tenant) {
		return ErrNotFound
	}
	tx, e := s.Store.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tx.Rollback(cleanup)
	}()
	if _, e = tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", s.Tenant); e != nil {
		return e
	}
	if e = fn(tx); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

type SavedConfig struct {
	Config   config.Config `json:"config"`
	Revision int           `json:"revision"`
	Status   string        `json:"status"`
	Hash     string        `json:"hash"`
	// Unchanged: the body equals the newest revision, so no new revision was made.
	Unchanged bool `json:"unchanged,omitempty"`
}

func (s Scope) SaveConfig(ctx context.Context, c config.Config) (out SavedConfig, err error) {
	if len(c.Validate()) > 0 {
		return out, errors.New("invalid_config")
	}
	body, e := json.Marshal(c)
	if e != nil {
		return out, e
	}
	sum := sha256.Sum256(body)
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", s.LockKey("version", c.ID)); e != nil {
			return e
		}
		hash := hex.EncodeToString(sum[:])
		// Saving an identical config again returns the newest revision instead of
		// piling up duplicate drafts that look like pending changes.
		var newest int
		var newestHash, newestStatus string
		e = tx.QueryRow(ctx, "SELECT version,config_hash,status FROM configs WHERE tenant_id=$1 AND id=$2 ORDER BY version DESC LIMIT 1", s.Tenant, c.ID).Scan(&newest, &newestHash, &newestStatus)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if newestHash == hash {
			out = SavedConfig{Config: c, Revision: newest, Status: newestStatus, Hash: hash, Unchanged: true}
			return nil
		}
		revision := newest + 1
		_, e = tx.Exec(ctx, "INSERT INTO configs(tenant_id,id,version,status,body,config_hash)VALUES($1,$2,$3,'draft',$4,$5)", s.Tenant, c.ID, revision, body, hash)
		out = SavedConfig{Config: c, Revision: revision, Status: "draft", Hash: hash}
		return e
	})
	return
}
func (s Scope) Config(ctx context.Context, id string, live bool) (out SavedConfig, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		q := "SELECT body,version,status,config_hash FROM configs WHERE tenant_id=$1 AND id=$2"
		if live {
			q += " AND status='live'"
		}
		q += " ORDER BY version DESC LIMIT 1"
		var body []byte
		e := tx.QueryRow(ctx, q, s.Tenant, id).Scan(&body, &out.Revision, &out.Status, &out.Hash)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		return json.Unmarshal(body, &out.Config)
	})
	return
}

// ConfigSummary is one connector's newest revision plus its live revision (0 = none).
type ConfigSummary struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Class    string    `json:"class"`
	Revision int       `json:"revision"`
	Status   string    `json:"status"`
	Hash     string    `json:"hash"`
	Live     int       `json:"live_revision"`
	Created  time.Time `json:"created_at"`
}

func (s Scope) Configs(ctx context.Context, limit, offset int) (out []ConfigSummary, err error) {
	out = []ConfigSummary{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT DISTINCT ON (c.id) c.id,COALESCE(c.body->>'name',''),COALESCE(c.body->'destination'->>'class',''),c.version,c.status,c.config_hash,c.created_at,
			COALESCE((SELECT MAX(l.version) FROM configs l WHERE l.tenant_id=c.tenant_id AND l.id=c.id AND l.status='live'),0)
			FROM configs c WHERE c.tenant_id=$1 ORDER BY c.id,c.version DESC LIMIT $2 OFFSET $3`, s.Tenant, limit, offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var c ConfigSummary
			if e = rows.Scan(&c.ID, &c.Name, &c.Class, &c.Revision, &c.Status, &c.Hash, &c.Created, &c.Live); e != nil {
				return e
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return
}
func (s Scope) Activate(ctx context.Context, id string, revision int) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		var locked bool
		if e := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))", s.LockKey("connector", id)).Scan(&locked); e != nil {
			return e
		}
		if !locked {
			return ErrBusy
		}
		var body []byte
		if e := tx.QueryRow(ctx, "SELECT body FROM configs WHERE tenant_id=$1 AND id=$2 AND version=$3", s.Tenant, id, revision).Scan(&body); errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		} else if e != nil {
			return e
		}
		var c config.Config
		if json.Unmarshal(body, &c) != nil || len(c.Validate()) > 0 {
			return errors.New("invalid_config")
		}
		if _, e := tx.Exec(ctx, "UPDATE configs SET status='approved' WHERE tenant_id=$1 AND id=$2 AND status='live'", s.Tenant, id); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, "UPDATE configs SET status='live' WHERE tenant_id=$1 AND id=$2 AND version=$3", s.Tenant, id, revision); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, "INSERT INTO sync_state(tenant_id,connector,next_due)VALUES($1,$2,now()) ON CONFLICT(tenant_id,connector) DO UPDATE SET next_due=now()", s.Tenant, id)
		if e != nil {
			return e
		}
		if c.Notifications == nil || !c.Notifications.Enabled {
			return s.resetAlerts(ctx, tx, id)
		}
		return nil
	})
}
func (s Scope) ConfigRevision(ctx context.Context, id string, revision int) (out SavedConfig, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		var body []byte
		e := tx.QueryRow(ctx, "SELECT body,version,status,config_hash FROM configs WHERE tenant_id=$1 AND id=$2 AND version=$3", s.Tenant, id, revision).Scan(&body, &out.Revision, &out.Status, &out.Hash)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		return json.Unmarshal(body, &out.Config)
	})
	return
}

// Lock holds a session lock on a dedicated connection and cancels work if that
// connection is lost. Every lock key includes the authenticated tenant.
func (s Scope) Lock(ctx context.Context, id string) (context.Context, func(), error) {
	if !config.ValidID(s.Tenant) {
		return ctx, nil, ErrNotFound
	}
	conn, e := s.Store.Pool.Acquire(ctx)
	if e != nil {
		return ctx, nil, e
	}
	key := s.LockKey("connector", id)
	var locked bool
	e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", key).Scan(&locked)
	if e != nil || !locked {
		conn.Release()
		if e != nil {
			return ctx, nil, e
		}
		return ctx, nil, ErrBusy
	}
	lease, cancel := context.WithCancel(ctx)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-lease.Done():
				return
			case <-tick.C:
				check, end := context.WithTimeout(lease, time.Second)
				e := conn.Ping(check)
				end()
				if e != nil {
					cancel()
					return
				}
			}
		}
	}()
	return lease, func() {
		close(stop)
		<-done
		cancel()
		clean, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		var ok bool
		if e := conn.QueryRow(clean, "SELECT pg_advisory_unlock(hashtextextended($1,0))", key).Scan(&ok); e != nil || !ok {
			conn.Conn().Close(clean)
		}
		conn.Release()
	}, nil
}
func (s Scope) StartRun(ctx context.Context, r model.Run) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "UPDATE runs SET outcome='interrupted',ended_at=now(),error='interrupted' WHERE tenant_id=$1 AND connector=$2 AND outcome='running'", s.Tenant, r.Connector); e != nil {
			return e
		}
		var window []byte
		if r.Incremental != nil {
			window, _ = json.Marshal(r.Incremental)
		}
		_, e := tx.Exec(ctx, "INSERT INTO runs(tenant_id,id,connector,config_version,config_hash,mode,started_at,outcome,incremental)VALUES($1,$2,$3,$4,$5,$6,$7,'running',$8)", s.Tenant, r.ID, r.Connector, r.ConfigVersion, r.ConfigHash, r.Mode, r.StartedAt, window)
		return e
	})
}
func (s Scope) SavePage(ctx context.Context, runID, source string, records []model.Record, bad []model.Rejection) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		var active bool
		if e := tx.QueryRow(ctx, "SELECT outcome='running' FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE", s.Tenant, runID).Scan(&active); e != nil {
			return e
		}
		if !active {
			return errors.New("run_interrupted")
		}
		for _, r := range records {
			if r.TenantID != s.Tenant || r.Source != source {
				return errors.New("record_scope_mismatch")
			}
			if r.ClassUID < 1 {
				return errors.New("invalid_class")
			}
			if _, e := tx.Exec(ctx, `INSERT INTO ocsf_records(tenant_id,source,external_id,class_uid,payload,fetched_at,run_id)VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,source,external_id) DO UPDATE SET class_uid=excluded.class_uid,payload=excluded.payload,fetched_at=excluded.fetched_at,run_id=excluded.run_id`, s.Tenant, source, r.ID, r.ClassUID, []byte(r.Payload), r.FetchedAt, runID); e != nil {
				return e
			}
		}
		for _, q := range bad {
			if _, e := tx.Exec(ctx, "INSERT INTO quarantine(tenant_id,run_id,source,page,record_index,field,reason)VALUES($1,$2,$3,$4,$5,$6,$7)", s.Tenant, runID, source, q.Page, q.Index, q.Field, q.Reason); e != nil {
				return e
			}
		}
		return nil
	})
}
func (s Scope) FinishRun(ctx context.Context, r model.Run, interval int) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		var window, checkpoint []byte
		if r.Incremental != nil {
			copy := *r.Incremental
			copy.Committed = r.Outcome == "success" && r.Quarantined == 0 && r.Mode == "live"
			if copy.Until.Before(copy.Since) {
				return incremental.ErrState
			}
			window, _ = json.Marshal(copy)
			if copy.Committed {
				checkpoint, _ = json.Marshal(incremental.Checkpoint{Version: 1, ConfigHash: r.ConfigHash, Through: copy.Until})
			}
		}
		tag, e := tx.Exec(ctx, "UPDATE runs SET ended_at=$3,outcome=$4,pages=$5,attempts=$6,received=$7,accepted=$8,quarantined=$9,error=$10,incremental=$11,skipped=$12 WHERE tenant_id=$1 AND id=$2 AND outcome='running'", s.Tenant, r.ID, r.EndedAt, r.Outcome, r.Pages, r.Attempts, r.Received, r.Accepted, r.Quarantined, r.Error, window, r.Skipped)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return errors.New("run_interrupted")
		}
		if interval < 1 {
			interval = 60
		}
		_, e = tx.Exec(ctx, `INSERT INTO sync_state(tenant_id,connector,last_success,next_due,watermark)VALUES($1,$2,CASE WHEN $3 THEN $4::timestamptz ELSE NULL END,now()+make_interval(secs=>$5),$6) ON CONFLICT(tenant_id,connector) DO UPDATE SET last_success=CASE WHEN $3 THEN $4::timestamptz ELSE sync_state.last_success END,next_due=now()+make_interval(secs=>$5),watermark=COALESCE($6,sync_state.watermark)`, s.Tenant, r.Connector, r.Outcome == "success", r.EndedAt, interval, checkpoint)
		if e != nil {
			return e
		}
		return s.queueAlert(ctx, tx, r)
	})
}

type Job struct{ Tenant, Connector string }

func (s *Store) Jobs(ctx context.Context, running bool) ([]Job, error) {
	q := "SELECT tenant_id,id FROM due_connectors()"
	if running {
		q = "SELECT tenant_id,id FROM running_connectors()"
	}
	rows, e := s.Pool.Query(ctx, q)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var j Job
		if e = rows.Scan(&j.Tenant, &j.Connector); e != nil {
			return nil, e
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
func (s *Store) Recover(ctx context.Context) error {
	jobs, e := s.Jobs(ctx, true)
	if e != nil {
		return e
	}
	for _, j := range jobs {
		scope := s.ForTenant(j.Tenant)
		_, release, e := scope.Lock(ctx, j.Connector)
		if errors.Is(e, ErrBusy) {
			continue
		}
		if e != nil {
			return e
		}
		e = scope.WithTx(ctx, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, "UPDATE runs SET outcome='interrupted',ended_at=now(),error='interrupted' WHERE tenant_id=$1 AND connector=$2 AND outcome='running'", j.Tenant, j.Connector)
			return e
		})
		release()
		if e != nil {
			return e
		}
	}
	return nil
}
func (s Scope) IsDue(ctx context.Context, id string) (due bool, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT next_due<=now() FROM sync_state WHERE tenant_id=$1 AND connector=$2", s.Tenant, id).Scan(&due)
	})
	return
}
func (s Scope) Runs(ctx context.Context, id string, limit, offset int) (out []model.Run, err error) {
	out = []model.Run{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT tenant_id,id,connector,config_version,config_hash,mode,started_at,ended_at,outcome,pages,attempts,received,accepted,quarantined,error,incremental,skipped FROM runs WHERE tenant_id=$1 AND ($2='' OR connector=$2) ORDER BY started_at DESC,id LIMIT $3 OFFSET $4`, s.Tenant, id, limit, offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var r model.Run
			var window []byte
			if e = rows.Scan(&r.TenantID, &r.ID, &r.Connector, &r.ConfigVersion, &r.ConfigHash, &r.Mode, &r.StartedAt, &r.EndedAt, &r.Outcome, &r.Pages, &r.Attempts, &r.Received, &r.Accepted, &r.Quarantined, &r.Error, &window, &r.Skipped); e != nil {
				return e
			}
			if len(window) > 0 && json.Unmarshal(window, &r.Incremental) != nil {
				return incremental.ErrState
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return
}

// Records returns stored OCSF events of one class (by class_uid), optionally for one source.
func (s Scope) Records(ctx context.Context, classUID int, source string, limit, offset int) (out []json.RawMessage, err error) {
	q := "SELECT payload FROM ocsf_records WHERE tenant_id=$1 AND class_uid=$5 AND ($2='' OR source=$2) ORDER BY source,external_id LIMIT $3 OFFSET $4"
	out = []json.RawMessage{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, q, s.Tenant, source, limit, offset, classUID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				return e
			}
			out = append(out, json.RawMessage(raw))
		}
		return rows.Err()
	})
	return
}

// PRDViews are the PRD "common schema (minimum)" views (migration 003).
var PRDViews = []string{"users", "devices", "events"}

// View reads one PRD view as JSON rows. name must be one of PRDViews; the view
// is security_invoker, so RLS on ocsf_records still scopes it to the tenant.
func (s Scope) View(ctx context.Context, name, source string, limit, offset int) (out []json.RawMessage, err error) {
	ok := false
	for _, v := range PRDViews {
		ok = ok || v == name
	}
	if !ok {
		return nil, ErrNotFound
	}
	q := "SELECT row_to_json(v) FROM " + pgx.Identifier{s.Store.namespace, name}.Sanitize() + " v WHERE tenant_id=$1 AND ($2='' OR source=$2) ORDER BY source,id LIMIT $3 OFFSET $4"
	out = []json.RawMessage{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, q, s.Tenant, source, limit, offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				return e
			}
			out = append(out, json.RawMessage(raw))
		}
		return rows.Err()
	})
	return
}
func (s Scope) Quarantine(ctx context.Context, id string, limit, offset int) (out []map[string]any, err error) {
	out = []map[string]any{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, "SELECT run_id,source,page,record_index,field,reason FROM quarantine WHERE tenant_id=$1 AND ($2='' OR source=$2) ORDER BY id DESC LIMIT $3 OFFSET $4", s.Tenant, id, limit, offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var run, source, field, reason string
			var page, index int
			if e = rows.Scan(&run, &source, &page, &index, &field, &reason); e != nil {
				return e
			}
			out = append(out, map[string]any{"tenant_id": s.Tenant, "run_id": run, "source": source, "page": page, "record_index": index, "field": field, "reason": reason})
		}
		return rows.Err()
	})
	return
}

type Health struct {
	TenantID    string     `json:"tenant_id"`
	Connector   string     `json:"connector"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	LastRun     *time.Time `json:"last_run"`
	LastSuccess *time.Time `json:"last_success"`
	Accepted    int        `json:"accepted"`
	Error       string     `json:"error"`
}

func (s Scope) Health(ctx context.Context, limit, offset int) (out []Health, err error) {
	out = []Health{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT c.id,c.body->>'name',COALESCE(r.outcome,'idle'),r.started_at,s.last_success,COALESCE(r.accepted,0),COALESCE(r.error,'') FROM configs c LEFT JOIN sync_state s ON s.tenant_id=c.tenant_id AND s.connector=c.id LEFT JOIN LATERAL(SELECT outcome,started_at,accepted,error FROM runs WHERE tenant_id=c.tenant_id AND connector=c.id ORDER BY started_at DESC LIMIT 1) r ON true WHERE c.tenant_id=$1 AND c.status='live' ORDER BY c.id LIMIT $2 OFFSET $3`, s.Tenant, limit, offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			h := Health{TenantID: s.Tenant}
			if e = rows.Scan(&h.Connector, &h.Name, &h.Status, &h.LastRun, &h.LastSuccess, &h.Accepted, &h.Error); e != nil {
				return e
			}
			switch h.Status {
			case "success":
				h.Status = "healthy"
			case "completed_with_errors", "incomplete":
				h.Status = "degraded"
			case "interrupted":
				h.Status = "failed"
			}
			switch h.Error {
			case "rate_limited", "auth_failed", "destination_denied", "timeout",
				"credential_missing", "credential_incomplete", "credential_binding_mismatch":
				h.Status = h.Error
			}
			out = append(out, h)
		}
		return rows.Err()
	})
	return
}
