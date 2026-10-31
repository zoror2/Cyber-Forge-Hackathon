package mapping

import (
	"configbridge/pkg/config"
	"configbridge/pkg/ocsf"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func ptr(s string) *string { return &s }

func decode(t *testing.T, payload json.RawMessage) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(payload, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Every shipped config must be valid against the pinned OCSF schema.
func TestShippedConfigsAreValidOCSF(t *testing.T) {
	files, _ := filepath.Glob("../../configs/*.json")
	if len(files) < 4 {
		t.Fatalf("expected shipped configs, found %d", len(files))
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if _, issues := config.Decode(b); len(issues) > 0 {
			t.Errorf("%s: %v", f, issues)
		}
	}
}

func TestFixtureBecomesVulnerabilityFindings(t *testing.T) {
	b, _ := os.ReadFile("../../configs/fixture_events.json")
	c, issues := config.Decode(b)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	raw, _ := os.ReadFile("testdata/events.json")
	var p any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	items, err := Items(p, c.ItemsPath)
	if err != nil {
		t.Fatal(err)
	}
	good, bad := 0, 0
	for i, row := range items {
		r, q := Map(row, c, "tenant-a", time.Now().UTC(), i)
		if q != nil {
			bad++
			if q.Field != "finding_info.uid" {
				t.Fatal(q)
			}
			continue
		}
		good++
		v := decode(t, r.Payload)
		if r.ClassUID != 2002 || v["class_uid"] != float64(2002) || ocsf.Get(v, "metadata.source") != "fixture_events" || ocsf.Get(v, "metadata.tenant_uid") != "tenant-a" {
			t.Fatal(v)
		}
		if ocsf.Get(v, "metadata.version") != ocsf.Version() {
			t.Fatal("metadata.version missing")
		}
	}
	if good != 3 || bad != 1 {
		t.Fatalf("got %d/%d", good, bad)
	}
}

func TestKEVRecordMapsToOCSF(t *testing.T) {
	b, _ := os.ReadFile("../../configs/cisa_kev.json")
	c, issues := config.Decode(b)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	row := map[string]any{
		"cveID": "CVE-2026-118527", "vendorProject": "Ivanti", "product": " Endpoint Manager (EPM)",
		"vulnerabilityName": "Ivanti Vulnerability", "dateAdded": "2026-10-30", "shortDescription": "desc",
		"requiredAction": "Apply mitigations", "dueDate": "2026-11-20", "knownRansomwareCampaignUse": "Known",
		"cwes": []any{"CWE-330"},
	}
	r, q := Map(row, c, "tenant-a", time.Now(), 0)
	if q != nil {
		t.Fatal(q)
	}
	v := decode(t, r.Payload)
	want := map[string]any{
		"finding_info.uid": "CVE-2026-118527", "vulnerabilities.0.cve.uid": "CVE-2026-118527",
		"vulnerabilities.0.vendor_name": "Ivanti", "vulnerabilities.0.is_exploit_available": true,
		"vulnerabilities.0.cwe.uid": "CWE-330", "unmapped.product": "Endpoint Manager (EPM)",
		"unmapped.ransomware_use": "Known", "metadata.product.vendor_name": "CISA",
		"time": float64(time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC).UnixMilli()), "severity": "Unknown",
	}
	for p, w := range want {
		if got := ocsf.Get(v, p); got != w {
			t.Errorf("%s = %#v, want %#v", p, got, w)
		}
	}
	// a KEV entry without CWEs still maps (cwe is optional; cve.uid is not)
	delete(row, "cwes")
	if _, q := Map(row, c, "tenant-a", time.Now(), 0); q != nil {
		t.Fatal(q)
	}
}

// Real NVD CVE API page (3 public CVEs, hasKev), recorded 2026-10-31.
func TestNVDPageMapsToOCSF(t *testing.T) {
	b, _ := os.ReadFile("../../configs/nvd_kev_cves.json")
	c, issues := config.Decode(b)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	raw, _ := os.ReadFile("testdata/nvd_kev_page.json")
	var p any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	items, err := Items(p, c.ItemsPath)
	if err != nil || len(items) != 3 {
		t.Fatal(err, len(items))
	}
	want := []struct {
		id       string
		severity float64
		score    float64
	}{{"CVE-2026-68820", 4, 7.0}, {"CVE-2026-71362", 5, 9.1}, {"CVE-2026-66384", 3, 5.3}}
	for i, row := range items {
		r, q := Map(row, c, "tenant-a", time.Now(), i)
		if q != nil {
			t.Fatal(q)
		}
		v := decode(t, r.Payload)
		if r.ID != want[i].id || v["severity_id"] != want[i].severity || ocsf.Get(v, "vulnerabilities.0.cve.cvss.0.base_score") != want[i].score ||
			ocsf.Get(v, "vulnerabilities.0.cve.cvss.0.version") != "3.1" || ocsf.Get(v, "finding_info.title") == "untitled" ||
			ocsf.Get(v, "unmapped.kev_date_added") == nil || ocsf.Get(v, "metadata.product.vendor_name") != "NIST" {
			t.Fatalf("%d: %v", i, v)
		}
	}
	// published "2026-08-11T17:19:06.357" is naive; the config pins it to UTC
	r, _ := Map(items[0], c, "tenant-a", time.Now(), 0)
	if decode(t, r.Payload)["time"] != float64(time.Date(2026, 8, 11, 17, 19, 6, 357e6, time.UTC).UnixMilli()) {
		t.Fatal("published time wrong")
	}
}

func TestUserInventoryNestedDefaultsAndDates(t *testing.T) {
	c := config.Config{ID: "source", Name: "Vendor", Destination: config.Destination{Class: "user_inventory", Mapping: map[string]config.Field{
		"user.uid": {Path: ptr("id"), Required: true, Transform: "string"}, "user.email_addr": {Path: ptr("profile.contacts.0.email")},
		"user.name":                        {Path: ptr("missing"), Default: "anonymous"},
		"user.ldap_person.last_login_time": {Path: ptr("last"), Transform: "datetime", Format: "02/01/2006 15:04", Timezone: "Asia/Kolkata"},
	}}}
	row := map[string]any{"id": 0, "last": "31/10/2026 15:30", "profile": map[string]any{"contacts": []any{map[string]any{"email": "demo@example.invalid"}}}}
	r, q := Map(row, c, "tenant-a", time.Now(), 0)
	if q != nil {
		t.Fatal(q)
	}
	v := decode(t, r.Payload)
	if r.ID != "0" || ocsf.Get(v, "user.name") != "anonymous" || ocsf.Get(v, "user.email_addr") != "demo@example.invalid" ||
		ocsf.Get(v, "user.ldap_person.last_login_time") != float64(time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC).UnixMilli()) ||
		ocsf.Get(v, "metadata.product.name") != "Vendor" {
		t.Fatal(v)
	}
}

func TestBadRecordsAndCollection(t *testing.T) {
	if _, err := Items(map[string]any{}, "items"); err == nil {
		t.Fatal("missing collection accepted")
	}
	if _, err := Items(map[string]any{"items": "oops"}, "items"); err == nil {
		t.Fatal("non-array accepted")
	}
	for _, value := range []string{"not-a-date", "2026-10-31T10:00:00"} {
		if _, err := transform(value, config.Field{Transform: "datetime"}); err == nil {
			t.Fatal("invalid or naive date accepted")
		}
	}
	c := config.Config{ID: "test", Destination: config.Destination{Class: "user_inventory", Mapping: map[string]config.Field{"user.uid": {Constant: " "}}}}
	if _, q := Map(map[string]any{}, c, "tenant-a", time.Now(), 0); q == nil {
		t.Fatal("blank ID accepted")
	}
}

func TestExactIDsLookupEnumsAndMalformedRows(t *testing.T) {
	c := config.Config{ID: "source", Destination: config.Destination{Class: "user_inventory", Mapping: map[string]config.Field{
		"user.uid":     {Path: ptr("id"), Transform: "string", Required: true},
		"user.type_id": {Path: ptr("role"), Transform: "lookup", Lookup: map[string]string{"ADMIN": "2", "BOGUS": "42"}},
	}}}
	r, q := Map(map[string]any{"id": json.Number("9007199254740993"), "role": "ADMIN"}, c, "tenant-a", time.Now(), 0)
	if q != nil || r.ID != "9007199254740993" {
		t.Fatal("large numeric ID lost precision", q)
	}
	if v := decode(t, r.Payload); ocsf.Get(v, "user.type_id") != float64(2) {
		t.Fatal("lookup to enum id failed", v)
	}
	// a lookup that produces a value outside the OCSF enum is quarantined
	if _, q := Map(map[string]any{"id": 1, "role": "BOGUS"}, c, "tenant-a", time.Now(), 0); q == nil || q.Field != "user.type_id" {
		t.Fatal("out-of-enum value accepted", q)
	}
	for _, row := range []any{nil, true, []any{}, map[string]any{"id": 1, "role": "unknown"}} {
		if _, q := Map(row, c, "tenant-a", time.Now(), 0); q == nil {
			t.Fatal("invalid row accepted")
		}
	}
	if v, e := transform("  x ", config.Field{Transform: "trim"}); e != nil || v != "x" {
		t.Fatal("trim failed")
	}
}

func TestFilterKeep(t *testing.T) {
	now := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	row := map[string]any{"ransom": "Known", "added": "2026-10-20", "vendor": "Ivanti", "n": json.Number("3")}
	cases := []struct {
		f    config.Condition
		keep bool
	}{
		{config.Condition{Path: "ransom", Op: "equals", Value: "Known"}, true},
		{config.Condition{Path: "ransom", Op: "equals", Value: "Unknown"}, false},
		{config.Condition{Path: "ransom", Op: "not_equals", Value: "Known"}, false},
		{config.Condition{Path: "missing", Op: "not_equals", Value: "x"}, true},
		{config.Condition{Path: "vendor", Op: "in", Value: []any{"Fortinet", "Ivanti"}}, true},
		{config.Condition{Path: "vendor", Op: "in", Value: []any{"Fortinet"}}, false},
		{config.Condition{Path: "added", Op: "within_days", Value: json.Number("30")}, true},
		{config.Condition{Path: "added", Op: "within_days", Value: json.Number("5")}, false},
		{config.Condition{Path: "missing", Op: "exists", Value: nil}, false},
		{config.Condition{Path: "missing", Op: "exists", Value: false}, true},
		{config.Condition{Path: "n", Op: "equals", Value: json.Number("3")}, true},
	}
	for _, tc := range cases {
		if got := Keep(row, []config.Condition{tc.f}, now); got != tc.keep {
			t.Errorf("%+v: keep=%v, want %v", tc.f, got, tc.keep)
		}
	}
	both := []config.Condition{cases[0].f, cases[5].f}
	if Keep(row, both, now) {
		t.Error("conditions must be ANDed")
	}
}

func TestConfigRejectsBadOCSFMappings(t *testing.T) {
	b, _ := os.ReadFile("../../configs/cisa_kev.json")
	base, _ := config.Decode(b)
	mutate := map[string]func(c *config.Config){
		"unknown class": func(c *config.Config) { c.Destination.Class = "users" },
		"unknown field": func(c *config.Config) { c.Destination.Mapping["finding_info.nope"] = config.Field{Constant: "x"} },
		"platform owned": func(c *config.Config) {
			c.Destination.Mapping["metadata.tenant_uid"] = config.Field{Constant: "tenant-b"}
		},
		"identity not required": func(c *config.Config) {
			f := c.Destination.Mapping["finding_info.uid"]
			f.Required = false
			c.Destination.Mapping["finding_info.uid"] = f
		},
		"ocsf required missing": func(c *config.Config) {
			for k := range c.Destination.Mapping {
				if len(k) > 15 && k[:15] == "vulnerabilities" {
					delete(c.Destination.Mapping, k)
				}
			}
		},
		"bad filter op": func(c *config.Config) { c.Filter = []config.Condition{{Path: "x", Op: "regex", Value: ".*"}} },
		"bad activity":  func(c *config.Config) { c.Destination.ActivityID = 42 },
		"bad filter in": func(c *config.Config) { c.Filter = []config.Condition{{Path: "x", Op: "in", Value: "notalist"}} },
		"bad days value": func(c *config.Config) {
			c.Filter = []config.Condition{{Path: "x", Op: "within_days", Value: json.Number("0")}}
		},
	}
	for name, m := range mutate {
		c := base
		c.Destination.Mapping = map[string]config.Field{}
		for k, v := range base.Destination.Mapping {
			c.Destination.Mapping[k] = v
		}
		m(&c)
		if len(c.Validate()) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}
