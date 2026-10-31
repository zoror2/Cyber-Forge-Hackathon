package tests

import (
	"configbridge/internal/engine"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"configbridge/pkg/mapping"
	"configbridge/pkg/model"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"os"
	"strings"
	"testing"
	"time"
)

func TestKEVExposureIsolationAndCredentialOwnership(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	raw, err := os.ReadFile("../configs/cisa_kev.json")
	if err != nil {
		t.Fatal(err)
	}
	kev, issues := config.Decode(raw)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		scope := e.db.Store.ForTenant(tenant)
		// Seed public feed fixtures via the actual mapper/store with the source's
		// canonical config. No internet or live CISA counts are assumed by this test.
		saved, err := scope.SaveConfig(ctx, kev)
		if err != nil {
			t.Fatal(err)
		}
		run := model.Run{TenantID: tenant, ID: "kev-run", Connector: kev.ID, ConfigVersion: saved.Revision, ConfigHash: saved.Hash, Mode: "live", StartedAt: time.Now()}
		if err = scope.StartRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		var records []model.Record
		for i := 0; i < 23; i++ {
			row := map[string]any{"cveID": fmt.Sprintf("CVE-2024-%05d", 10000+i), "dateAdded": "2024-10-01", "vulnerabilityName": "Synthetic KEV fixture", "vendorProject": " Ivanti ", "product": " Endpoint Manager (EPM) "}
			rec, bad := mapping.Map(row, kev, tenant, time.Now(), i)
			if bad != nil {
				t.Fatal(bad)
			}
			records = append(records, rec)
		}
		// Malformed CVE IDs and unrelated event types must not create findings.
		invalid := map[string]any{"cveID": "injected-text", "dateAdded": "2024-10-01", "vulnerabilityName": "Fixture", "vendorProject": "Ivanti", "product": "Endpoint Manager (EPM)"}
		rec, bad := mapping.Map(invalid, kev, tenant, time.Now(), 23)
		if bad != nil {
			t.Fatal(bad)
		}
		records = append(records, rec)
		// a vendor with no alias row: matched by name alone
		for i, product := range []string{"FortiOS", "FortiProxy"} {
			rec, bad := mapping.Map(map[string]any{"cveID": fmt.Sprintf("CVE-2025-%05d", 20000+i), "dateAdded": "2025-01-02", "vulnerabilityName": "Synthetic", "vendorProject": "Fortinet", "product": product}, kev, tenant, time.Now(), 30+i)
			if bad != nil {
				t.Fatal(bad)
			}
			records = append(records, rec)
		}
		if err = scope.SavePage(ctx, run.ID, kev.ID, records, nil); err != nil {
			t.Fatal(err)
		}
		if err = scope.SavePage(ctx, run.ID, kev.ID, records, nil); err != nil {
			t.Fatal(err)
		}
		finished := time.Now()
		run.EndedAt = &finished
		run.Outcome = "success"
		if err = scope.FinishRun(ctx, run, 86400); err != nil {
			t.Fatal(err)
		}
		c := kev
		c.ID = tenant + "-ivanti"
		c.Vendor = "Ivanti"
		c.Auth = engine.Auth{Type: "bearer", Secret: "same-name"}
		c.Request.URL = "https://api.example.com/events"
		saved, err = scope.SaveConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if err = scope.Activate(ctx, c.ID, saved.Revision); err != nil {
			t.Fatal(err)
		}
		e.request(t, tenant, "PUT", "/secrets/same-name", []byte(`{"value":"SYNTHETIC-PRIVATE-SENTINEL","allowed_hosts":["api.example.com"]}`), 204)
		caller, err := e.db.Store.AuthenticateCaller(ctx, key(tenant))
		if err != nil {
			t.Fatal(err)
		}
		out := e.request(t, tenant, "GET", "/exposure", nil, 200)
		if strings.Contains(string(out), "SYNTHETIC-PRIVATE-SENTINEL") || strings.Contains(string(out), "key_hash") {
			t.Fatal("secret leaked")
		}
		var results []store.Exposure
		if err = json.Unmarshal(out, &results); err != nil {
			t.Fatal(err)
		}
		if len(results) != 1 || results[0].Connector != c.ID || results[0].KEVCount != 23 || len(results[0].CVEIDs) != 20 || results[0].Assessment != "vendor_match_requires_deployment_review" {
			t.Fatalf("bad exposure result %s", out)
		}
		if len(results[0].Credentials) != 1 || results[0].Credentials[0].ID == "" || results[0].Credentials[0].Owner != caller.Actor {
			t.Fatal("incorrect owner", results)
		}
		id := results[0].Credentials[0].ID
		e.request(t, tenant, "PUT", "/secrets/same-name", []byte(`{"value":"SYNTHETIC-ROTATED","allowed_host":"api.example.com"}`), 204)
		secret, err := e.svc.Get(ctx, tenant, "same-name")
		if err != nil || secret.ID() != id {
			t.Fatal("rotation changed credential id", err)
		}
		e.request(t, tenant, "PUT", "/secrets/forged", []byte(`{"value":"x","allowed_host":"api.example.com","owner":"someone-else"}`), 400)
		e.request(t, tenant, "PUT", "/secrets/forged", []byte(`{"value":"x","allowed_hosts":["*.example.com"]}`), 422)
		c.ID = "no-match"
		c.Vendor = "Unknown vendor"
		saved, err = scope.SaveConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if err = scope.Activate(ctx, c.ID, saved.Revision); err != nil {
			t.Fatal(err)
		}
		if string(e.request(t, tenant, "GET", "/exposure?connector=no-match", nil, 200)) != "[]\n" {
			t.Fatal("nonmatching vendor returned")
		}
		if string(e.request(t, tenant, "GET", "/exposure?offset=1&limit=1", nil, 200)) != "[]\n" {
			t.Fatal("pagination failed")
		}
		c.ID = "fortinet-fw"
		c.Vendor = "  FORTINET "
		saved, err = scope.SaveConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if err = scope.Activate(ctx, c.ID, saved.Revision); err != nil {
			t.Fatal(err)
		}
		var forti []store.Exposure
		json.Unmarshal(e.request(t, tenant, "GET", "/exposure?connector=fortinet-fw", nil, 200), &forti)
		if len(forti) != 1 || forti[0].KEVCount != 2 || len(forti[0].Products) != 2 {
			t.Fatal("vendor outside the alias list not matched", forti)
		}
	}
	e.request(t, "tenant-b", "GET", "/exposure?connector=tenant-a-ivanti", nil, 404)
	e.request(t, "tenant-a", "GET", "/exposure?limit=501", nil, 400)
	err = e.db.Store.ForTenant("tenant-a").WithTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO vendor_aliases VALUES('evil','anything','Ivanti')")
		return err
	})
	if err == nil {
		t.Fatal("tenant could edit reviewed aliases")
	}
	// CISA's exact official mirror is the same reviewed feed; arbitrary GitHub
	// repositories and other hosts still cannot establish CISA provenance.
	if _, err = e.db.Admin.Exec(ctx, "UPDATE "+e.db.Schema+".configs SET body=jsonb_set(body,'{request,url}','\"https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json\"') WHERE id='cisa_kev'"); err != nil {
		t.Fatal(err)
	}
	var mirrored []store.Exposure
	if err = json.Unmarshal(e.request(t, "tenant-a", "GET", "/exposure?connector=tenant-a-ivanti", nil, 200), &mirrored); err != nil || len(mirrored) != 1 || mirrored[0].KEVCount != 23 {
		t.Fatal("official CISA mirror lost provenance", mirrored, err)
	}
	// Changing the producing revision's URL simulates a non-CISA source: ignored.
	if _, err = e.db.Admin.Exec(ctx, "UPDATE "+e.db.Schema+".configs SET body=jsonb_set(body,'{request,url}','\"https://other.example.com\"') WHERE id='cisa_kev'"); err != nil {
		t.Fatal(err)
	}
	if string(e.request(t, "tenant-a", "GET", "/exposure", nil, 200)) != "[]\n" {
		t.Fatal("untrusted feed counted as CISA")
	}
}
