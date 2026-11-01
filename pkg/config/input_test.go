package config

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestJSONAndYAMLNormalizeToSameConfig(t *testing.T) {
	body, err := os.ReadFile("../../configs/fixture_events.json")
	if err != nil {
		t.Fatal(err)
	}
	expected, issues := Decode(body)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	var generic any
	if err = json.Unmarshal(body, &generic); err != nil {
		t.Fatal(err)
	}
	encoded, err := yaml.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string][]byte{"json": body, "yaml": encoded, "yaml_comments": append([]byte("# customer config\n---\n"), encoded...)} {
		t.Run(name, func(t *testing.T) {
			actual, issues := DecodeInput(input)
			if len(issues) > 0 {
				t.Fatal(issues)
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatal("format changed config semantics")
			}
		})
	}
}

func TestYAMLInputRejectsAmbiguityAndUnsafeSettings(t *testing.T) {
	for name, input := range map[string]string{
		"empty": "", "scalar": "hello", "sequence": "- version: 1", "duplicate": "version: 1\nversion: 2", "nested_duplicate": "request:\n  url: https://good.example\n  url: https://bad.example",
		"alias": "request: &request {url: https://example.com}\ncopy: *request", "merge": "request: {<<: {method: GET}}", "tag": "request: !execute SENTINEL", "binary": "id: !!binary U0VOVElORUw=", "non_string_key": "1: value", "documents": "version: 1\n---\nversion: 2", "nan": "value: .nan", "infinity": "value: .inf", "hex": "version: 0x01", "tenant": "tenant_id: SENTINEL", "unknown": "execute: SENTINEL", "oversize": strings.Repeat("x", MaxBytes+1), "depth": strings.Repeat("[", 35) + "1" + strings.Repeat("]", 35),
	} {
		t.Run(name, func(t *testing.T) {
			_, issues := DecodeInput([]byte(input))
			if len(issues) == 0 {
				t.Fatal("unsafe YAML accepted")
			}
			b, _ := json.Marshal(issues)
			if strings.Contains(string(b), "SENTINEL") {
				t.Fatal("input echoed in error")
			}
		})
	}
}

func TestYAMLNumbersAndDateConstantsRemainExact(t *testing.T) {
	input := `version: 1
id: yaml_numbers
name: YAML example
request:
  url: https://example.com/users
destination:
  class: user_inventory
  mapping:
    user.uid:
      constant: 9007199254740993
      required: true
    unmapped.date:
      constant: 2026-11-01
`
	c, issues := DecodeInput([]byte(input))
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	if c.Destination.Mapping["user.uid"].Constant != json.Number("9007199254740993") {
		t.Fatal("integer precision lost")
	}
	if c.Destination.Mapping["unmapped.date"].Constant != "2026-11-01" {
		t.Fatal("date implicitly converted")
	}
	flow := "{version: 1, id: yaml_flow, name: Flow, request: {url: 'https://example.com/users'}, destination: {class: user_inventory, mapping: {user.uid: {path: id, required: true}}}}"
	if _, issues = DecodeInput([]byte(flow)); len(issues) > 0 {
		t.Fatal("valid flow YAML rejected", issues)
	}
}
