package mapping

import (
	"configbridge/pkg/config"
	"configbridge/pkg/ocsf"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestVendorDocumentedResponsesMap(t *testing.T) {
	for _, tc := range []struct{ file, body, identity, field, want string }{
		{"sophos_central_endpoints.json", `{"id":"endpoint-1","hostname":"test-device","ipv4Addresses":["10.0.0.1"]}`, "device.uid", "device.hostname", "test-device"},
		{"trellix_edr_alerts.json", `{"id":"unique-alert-1","type":"alerts","attributes":{"Activity":"Threat Detected","DetectionDate":"2024-06-19T07:44:55.708+00:00","Severity":"s0"}}`, "finding_info.uid", "finding_info.title", "Threat Detected"},
		{"elastic_security_alerts.json", `{"_id":"alert-1","fields":{"kibana.alert.rule.name":["Correct rule"],"kibana.alert.severity":["high"],"@timestamp":["2026-11-01T00:00:00Z"]}}`, "finding_info.uid", "finding_info.title", "Correct rule"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			raw, err := os.ReadFile("../../configs/" + tc.file)
			if err != nil {
				t.Fatal(err)
			}
			cfg, issues := config.Decode(raw)
			if len(issues) != 0 {
				t.Fatal(issues)
			}
			var row any
			if err := json.Unmarshal([]byte(tc.body), &row); err != nil {
				t.Fatal(err)
			}
			record, bad := Map(row, cfg, "test-tenant", time.Now(), 0)
			if bad != nil {
				t.Fatal(bad)
			}
			var event map[string]any
			if err := json.Unmarshal(record.Payload, &event); err != nil {
				t.Fatal(err)
			}
			if ocsf.Get(event, tc.identity) == nil || ocsf.Get(event, tc.field) != tc.want {
				t.Fatal("mapping lost documented fields", event)
			}
		})
	}
}
