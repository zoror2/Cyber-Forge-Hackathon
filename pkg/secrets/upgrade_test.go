package secrets

import (
	"bytes"
	"configbridge/internal/egress"
	"configbridge/internal/engine"
	"configbridge/internal/store"
	"configbridge/internal/testutil"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestVersionOneUpgradePreservesEncryptedCredentials(t *testing.T) {
	db := testutil.Setup(t)
	ctx := context.Background()
	schema := "legacy_" + strings.TrimPrefix(db.Schema, "test_")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := db.Admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE") })
	vendor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != `Bearer {"value":"LEGACY_LITERAL"}` {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(w, `[{"id":"legacy"}]`)
	}))
	defer vendor.Close()
	u, _ := url.Parse(vendor.URL)
	host := u.Host
	keys := map[string]string{"tenant-a": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))}
	local, err := NewLocal(nil, keys)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := local.seal("tenant-a", "legacy", `{"value":"LEGACY_LITERAL"}`, host)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SET LOCAL search_path="+quoted); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../internal/store/migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	var owner string
	if err = tx.QueryRow(ctx, "SELECT current_user").Scan(&owner); err != nil {
		t.Fatal(err)
	}
	ownerLiteral := "'" + strings.ReplaceAll(owner, "'", "''") + "'"
	policies := ""
	for _, table := range []string{"tenants", "api_keys", "configs", "credentials_meta", "credentials_values", "runs", "users", "devices", "events", "quarantine", "sync_state"} {
		q := pgx.Identifier{schema, table}.Sanitize()
		policies += fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY; ALTER TABLE %s FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_isolation ON %s USING(tenant_id=current_setting('app.tenant_id',true) OR current_user=%s) WITH CHECK(tenant_id=current_setting('app.tenant_id',true) OR current_user=%s);", q, q, q, ownerLiteral, ownerLiteral)
	}
	sql := strings.ReplaceAll(string(raw), "__SCHEMA__", quoted)
	sql = strings.Replace(sql, "__RLS_POLICIES__", policies, 1)
	if _, err = tx.Exec(ctx, sql); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "CREATE TABLE schema_migrations(version integer PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now());INSERT INTO schema_migrations(version)VALUES(1);INSERT INTO tenants(tenant_id)VALUES('tenant-a')"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "INSERT INTO credentials_meta(tenant_id,name,allowed_host,backend)VALUES('tenant-a','legacy',$1,'local')", host); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "INSERT INTO credentials_values(tenant_id,name,ciphertext)VALUES('tenant-a','legacy',$1)", cipher); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	changeSchema := func(dsn string) string {
		u, e := url.Parse(dsn)
		if e != nil {
			t.Fatal(e)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	dsn := changeSchema(db.AdminDSN)
	for i := 0; i < 2; i++ {
		if err = store.Migrate(ctx, dsn, db.Role); err != nil {
			t.Fatal("upgrade failed", err)
		}
	}
	runtime, err := store.Open(ctx, changeSchema(db.AppDSN))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Pool.Close()
	local.Store = runtime
	svc := &Service{Store: runtime, Backend: local, BackendName: "local"}
	secret, err := svc.Get(ctx, "tenant-a", "legacy")
	if err != nil || secret.ID() == "" {
		t.Fatal("legacy secret unavailable", err)
	}
	meta, err := svc.List(ctx, "tenant-a", 10, 0)
	if err != nil || len(meta) != 1 || meta[0].Owner != "legacy:unknown" {
		t.Fatal("legacy ownership fabricated", err)
	}
	policy := egress.Policy{RootCAs: vendor.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, AllowPrivate: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	var port int
	fmt.Sscan(u.Port(), &port)
	c := engine.Connector{TenantID: "tenant-a", ID: "legacy", Request: engine.Request{URL: vendor.URL, AllowedPorts: []int{port}}, Auth: engine.Auth{Type: "bearer", Secret: "legacy"}}
	if _, err = engine.New(svc, policy, nil).Fetch(ctx, c, func(engine.Page) error { return nil }); err != nil {
		t.Fatal("upgraded legacy value changed", err)
	}
	if err = svc.PutCredential(ctx, store.Caller{Tenant: "tenant-a", Actor: "api_key:synthetic"}, "legacy", Input{Value: "rotated", Host: host}); err != nil {
		t.Fatal(err)
	}
	updated, err := svc.List(ctx, "tenant-a", 10, 0)
	if err != nil || updated[0].ID != meta[0].ID || updated[0].CreatedBy != "legacy:unknown" || updated[0].RotatedBy != "api_key:synthetic" {
		t.Fatal("rotation lost metadata", err)
	}
}
