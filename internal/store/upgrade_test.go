package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Reproduce the historical member-b schema, including its version-6 SIEM
// migration. Only disposable schemas in TEST_DATABASE_URL are modified.
func TestHistoricalSIEMUpgradePreservesRecordsAndMetering(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(admin.Close)
	suffix := fmt.Sprintf("upgrade_%d", time.Now().UnixNano())
	role := suffix + "_app"
	schema := pgx.Identifier{suffix}.Sanitize()
	quotedRole := pgx.Identifier{role}.Sanitize()
	if _, e = admin.Exec(ctx, "CREATE ROLE "+quotedRole+" LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'synthetic-test-only'; CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE; DROP ROLE "+quotedRole) })
	u, _ := url.Parse(dsn)
	q := u.Query()
	q.Set("search_path", suffix)
	u.RawQuery = q.Encode()
	scoped, e := pgxpool.New(ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	defer scoped.Close()
	var owner string
	if e = scoped.QueryRow(ctx, "SELECT current_user").Scan(&owner); e != nil {
		t.Fatal(e)
	}
	if _, e = scoped.Exec(ctx, "CREATE TABLE schema_migrations(version integer PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now())"); e != nil {
		t.Fatal(e)
	}
	old := append([]struct {
		version int
		sql     string
		tables  []string
	}{}, migrations[:5]...)
	old = append(old, struct {
		version int
		sql     string
		tables  []string
	}{6, migrationSIEM, []string{"siem_snapshots", "siem_findings", "ai_requests"}})
	for _, m := range old {
		policies := ""
		for _, table := range m.tables {
			quoted := pgx.Identifier{suffix, table}.Sanitize()
			policies += fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY; ALTER TABLE %s FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_isolation ON %s USING (tenant_id=current_setting('app.tenant_id',true) OR current_user=%s) WITH CHECK (tenant_id=current_setting('app.tenant_id',true) OR current_user=%s);", quoted, quoted, quoted, literal(owner), literal(owner))
		}
		sql := strings.ReplaceAll(m.sql, "__SCHEMA__", schema)
		sql = strings.Replace(sql, "__RLS_POLICIES__", policies, 1)
		if _, e = scoped.Exec(ctx, sql); e != nil {
			t.Fatal(m.version, e)
		}
		if _, e = scoped.Exec(ctx, "INSERT INTO schema_migrations(version)VALUES($1)", m.version); e != nil {
			t.Fatal(e)
		}
	}
	_, e = scoped.Exec(ctx, `INSERT INTO tenants(tenant_id)VALUES('historical');
INSERT INTO configs(tenant_id,id,version,status,body,config_hash)VALUES('historical','old',1,'live','{}','hash');
INSERT INTO runs(tenant_id,id,connector,config_version,config_hash,mode,started_at,outcome)VALUES('historical','run','old',1,'hash','live',now(),'success');
INSERT INTO users VALUES('historical','old','user','{"id":"user"}',now(),'run');
INSERT INTO devices VALUES('historical','old','device','{"id":"device"}',now(),'run');
INSERT INTO events VALUES('historical','old','event','{"id":"event"}',now(),'run');
INSERT INTO siem_snapshots VALUES('historical','old','generation',now(),now(),false);
INSERT INTO ai_requests(tenant_id,request_id,operation,provider,model,reserved_tokens,input_tokens,output_tokens,total_tokens)VALUES('historical','spent','config_draft','fixture','fixture',40000,10,20,30);`)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e = Migrate(ctx, u.String(), role); e != nil {
			t.Fatal("upgrade", i, e)
		}
	}
	for _, table := range []string{"legacy_users", "legacy_devices", "legacy_events", "siem_snapshots", "ai_requests"} {
		var n int
		if e = scoped.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{suffix, table}.Sanitize()).Scan(&n); e != nil || n != 1 {
			t.Fatal("lost historical data", table, n, e)
		}
	}
	var versions int
	if e = scoped.QueryRow(ctx, "SELECT count(*) FROM schema_migrations WHERE version IN (6,12)").Scan(&versions); e != nil || versions != 2 {
		t.Fatal("version collision", versions, e)
	}
	var tokens int
	if e = scoped.QueryRow(ctx, "SELECT total_tokens FROM ai_requests WHERE request_id='spent'").Scan(&tokens); e != nil || tokens != 30 {
		t.Fatal("metering lost", tokens, e)
	}
	var allowed bool
	for _, table := range []string{"legacy_users", "legacy_devices", "legacy_events"} {
		if e = scoped.QueryRow(ctx, "SELECT has_table_privilege($1,$2,'SELECT')", role, suffix+"."+table).Scan(&allowed); e != nil || allowed {
			t.Fatal("archive exposed", table, allowed, e)
		}
	}
	// Simulate databases already migrated by the original OCSF release,
	// which had no archive tables. Re-running Migrate must still work.
	for _, table := range []string{"legacy_users", "legacy_devices", "legacy_events"} {
		if _, e = scoped.Exec(ctx, "DROP TABLE "+pgx.Identifier{suffix, table}.Sanitize()); e != nil {
			t.Fatal(e)
		}
	}
	if e = Migrate(ctx, u.String(), role); e != nil {
		t.Fatal("existing OCSF database without archives", e)
	}
}
