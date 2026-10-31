package mapping

import (
	"configbridge/pkg/config"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestKEVVendorProductMapping(t *testing.T) {
	b, err := os.ReadFile("../../configs/cisa_kev.json")
	if err != nil {
		t.Fatal(err)
	}
	c, issues := config.Decode(b)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	row := map[string]any{"cveID": "CVE-2024-99999", "dateAdded": "2024-10-01", "vulnerabilityName": "Synthetic fixture", "vendorProject": " Ivanti ", "product": " Endpoint Manager (EPM)\u00a0"}
	rec, bad := Map(row, c, "tenant-a", time.Now(), 0)
	if bad != nil {
		t.Fatal(bad)
	}
	var f struct {
		Vulns []struct {
			Vendor string `json:"vendor_name"`
		} `json:"vulnerabilities"`
		Unmapped struct {
			Product string `json:"product"`
		} `json:"unmapped"`
	}
	if err = json.Unmarshal(rec.Payload, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vulns) != 1 || f.Vulns[0].Vendor != "Ivanti" || f.Unmapped.Product != "Endpoint Manager (EPM)" {
		t.Fatalf("incorrect KEV mapping: %s", rec.Payload)
	}
	delete(row, "vendorProject")
	delete(row, "product")
	if _, bad = Map(row, c, "tenant-a", time.Now(), 0); bad != nil {
		t.Fatal("optional fields rejected", bad)
	}
	row["product"] = map[string]any{"bad": "value"}
	if _, bad = Map(row, c, "tenant-a", time.Now(), 0); bad == nil {
		t.Fatal("object accepted as product")
	}
	c.Vendor = "   "
	if len(c.Validate()) == 0 {
		t.Fatal("blank vendor accepted")
	}
	c.Vendor = strings.Repeat("x", 201)
	if len(c.Validate()) == 0 {
		t.Fatal("oversized vendor accepted")
	}
	c.Vendor = "Atlassian"
	if len(c.Validate()) != 0 {
		t.Fatal(c.Validate())
	}
	// Existing string mappings retain their exact original value.
	got, err := transform(" padded ", config.Field{Transform: "string"})
	if err != nil || got != " padded " {
		t.Fatal("trim changed existing string behavior")
	}
}
