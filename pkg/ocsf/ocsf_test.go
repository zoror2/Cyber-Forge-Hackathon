package ocsf

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func class(t *testing.T, name string) *Class {
	t.Helper()
	c, ok := Lookup(name)
	if !ok {
		t.Fatalf("class %s missing from pinned schema", name)
	}
	return c
}

func TestPinnedSchema(t *testing.T) {
	if Version() != "1.9.0" {
		t.Fatalf("version %s", Version())
	}
	want := map[string]int{"vulnerability_finding": 2002, "detection_finding": 2004, "user_inventory": 5003, "inventory_info": 5001, "authentication": 3002}
	for name, uid := range want {
		if c := class(t, name); c.UID != uid {
			t.Errorf("%s uid %d, want %d", name, c.UID, uid)
		}
		if _, ok := Identity[name]; !ok {
			t.Errorf("%s has no identity field", name)
		}
	}
}

func TestResolve(t *testing.T) {
	vf := class(t, "vulnerability_finding")
	for _, ok := range []string{"finding_info.uid", "vulnerabilities.0.cve.uid", "vulnerabilities.0.vendor_name", "vulnerabilities.0.is_exploit_available", "severity_id", "time", "metadata.product.name", "unmapped.ransomware_use"} {
		if _, err := Resolve(vf, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "nope", "finding_info", "vulnerabilities.cve.uid", "vulnerabilities.10.cve.uid", "class_uid", "metadata.tenant_uid", "metadata.source", "raw_data", "severity", "unmapped.Bad-Key", "unmapped.a.b", "time.x"} {
		if _, err := Resolve(vf, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCoerce(t *testing.T) {
	vf := class(t, "vulnerability_finding")
	sev, _ := Resolve(vf, "severity_id")
	if v, err := Coerce(sev, "4"); err != nil || v != int64(4) {
		t.Fatalf("severity from lookup string: %v %v", v, err)
	}
	if _, err := Coerce(sev, 42); err == nil {
		t.Fatal("severity_id 42 is not in the enum")
	}
	ts, _ := Resolve(vf, "time")
	day := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	if v, _ := Coerce(ts, day); v != day.UnixMilli() {
		t.Fatalf("timestamp_t must be epoch ms, got %v", v)
	}
	b, _ := Resolve(vf, "vulnerabilities.0.is_exploit_available")
	if v, err := Coerce(b, "true"); err != nil || v != true {
		t.Fatalf("bool: %v %v", v, err)
	}
	s, _ := Resolve(vf, "finding_info.uid")
	if _, err := Coerce(s, map[string]any{}); err == nil {
		t.Fatal("object accepted as string")
	}
}

func TestBuildKEVFinding(t *testing.T) {
	vf := class(t, "vulnerability_finding")
	fetched := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	doc, err := Build(vf, map[string]any{
		"finding_info.uid":              "CVE-2026-118527",
		"finding_info.title":            "Ivanti Connect Secure Vulnerability",
		"vulnerabilities.0.cve.uid":     "CVE-2026-118527",
		"vulnerabilities.0.vendor_name": "Ivanti",
		"unmapped.ransomware_use":       "Unknown",
	}, Context{Tenant: "tenant-a", Source: "cisa_kev", Product: "CISA KEV", Fetched: fetched})
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]any{
		"class_uid": 2002, "category_uid": 2, "activity_id": 1, "type_uid": 200201,
		"type_name": "Vulnerability Finding: Create", "severity_id": int64(0), "severity": "Unknown",
		"time": fetched.UnixMilli(), "metadata.version": "1.9.0", "metadata.tenant_uid": "tenant-a",
		"metadata.source": "cisa_kev", "metadata.product.name": "CISA KEV",
		"vulnerabilities.0.cve.uid": "CVE-2026-118527",
	}
	for p, want := range checks {
		if got := Get(doc, p); got != want {
			t.Errorf("%s = %#v, want %#v", p, got, want)
		}
	}
	if _, err := json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRejects(t *testing.T) {
	vf := class(t, "vulnerability_finding")
	ctx := Context{Tenant: "t", Source: "s", Product: "p", Fetched: time.Now()}
	var fe *FieldError
	// required by OCSF: vulnerabilities, finding_info.uid, cve.uid inside a present cve
	for name, mapped := range map[string]map[string]any{
		"no vulnerabilities": {"finding_info.uid": "x"},
		"no finding uid":     {"finding_info.title": "x", "vulnerabilities.0.cve.uid": "x"},
		"cve without uid":    {"finding_info.uid": "x", "vulnerabilities.0.cve.title": "x"},
		"gap in array":       {"finding_info.uid": "x", "vulnerabilities.1.cve.uid": "x"},
	} {
		if _, err := Build(vf, mapped, ctx); !errors.As(err, &fe) {
			t.Errorf("%s: want FieldError, got %v", name, err)
		}
	}
	if _, err := Build(vf, map[string]any{"finding_info.uid": "x", "vulnerabilities.0.cve.uid": "x"}, Context{ActivityID: 42, Fetched: time.Now()}); err == nil {
		t.Error("activity 42 accepted")
	}
}

func TestBuildUserInventory(t *testing.T) {
	ui := class(t, "user_inventory")
	doc, err := Build(ui, map[string]any{"user.uid": "103866", "user.name": "EnDe"}, Context{Tenant: "t", Source: "github_members", Product: "GitHub", Fetched: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if Get(doc, "type_uid") != 500302 || Get(doc, "activity_name") != "Collect" {
		t.Fatalf("inventory defaults wrong: %v %v", Get(doc, "type_uid"), Get(doc, "activity_name"))
	}
}
