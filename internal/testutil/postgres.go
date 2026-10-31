// Package testutil provisions isolated schemas and a real non-owner runtime role
// for PostgreSQL tests. It is never used by application entry points.
package testutil

import (
	"configbridge/internal/store"
	"context"
	"crypto/rand"
	"encoding/hex"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/url"
	"os"
	"strings"
	"testing"
)

type DB struct {
	Store                          *store.Store
	Admin                          *pgxpool.Pool
	AdminDSN, AppDSN, Role, Schema string
}

func Setup(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required for actual PostgreSQL tests")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 8)
	rand.Read(b)
	suffix := hex.EncodeToString(b)
	schema := "test_" + suffix
	role := "app_" + suffix
	if _, e = admin.Exec(ctx, "CREATE ROLE "+role+" LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'test-only-password'"); e != nil {
		admin.Close()
		t.Fatal(e)
	}
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	adminDSN := u.String()
	if e = store.Migrate(ctx, adminDSN, role); e != nil {
		t.Fatal(e)
	}
	if e = store.Migrate(ctx, adminDSN, role); e != nil {
		t.Fatal("migration not repeatable", e)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if e = store.Bootstrap(ctx, adminDSN, tenant, strings.Repeat(tenant+"-key-", 4), "kms-"+tenant); e != nil {
			t.Fatal(e)
		}
	}
	u.User = url.UserPassword(role, "test-only-password")
	s, e := store.Open(ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		s.Pool.Close()
		admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Exec(context.Background(), "DROP ROLE "+role)
		admin.Close()
	})
	return &DB{s, admin, adminDSN, u.String(), role, schema}
}
