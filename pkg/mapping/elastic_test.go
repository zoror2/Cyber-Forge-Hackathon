package mapping

import (
	"encoding/json"
	"testing"
)

// Elasticsearch's fields API returns literal dotted keys and array values.
// A nested field with the same spelling must never be selected accidentally.
func TestElasticLiteralFieldNamesAreUnambiguous(t *testing.T) {
	var row any
	if err := json.Unmarshal([]byte(`{"fields":{"kibana.alert.rule.name":["Correct rule"],"kibana":{"alert":{"rule":{"name":["Wrong nested rule"]}}},"a/b":["slash"],"a~b":["tilde"]}}`), &row); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"/fields/kibana.alert.rule.name/0": "Correct rule",
		"fields.kibana.alert.rule.name.0":  "Wrong nested rule",
		"/fields/a~1b/0":                   "slash", "/fields/a~0b/0": "tilde",
	} {
		got, ok := Path(row, path)
		if !ok || got != want {
			t.Errorf("%s: got %v, found=%v; want %s", path, got, ok, want)
		}
	}
}
