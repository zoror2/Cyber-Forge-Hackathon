package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// DecodeInput accepts JSON or a strict, data-only YAML document, then uses the
// exact canonical JSON validator. No network, AI call or config save occurs here.
// Decode remains JSON-only for stored revisions and model output contracts.
func DecodeInput(body []byte) (Config, []Issue) {
	if len(body) > MaxBytes {
		return Config{}, []Issue{{"config", "exceeds 256 KiB"}}
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return Config{}, []Issue{{"config", "a JSON or YAML config is required"}}
	}
	if json.Valid(trimmed) {
		return Decode(body)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	var document yaml.Node
	invalid := func() (Config, []Issue) {
		return Config{}, []Issue{{"config", "invalid YAML: use one mapping document with unique string keys, JSON-compatible scalar values, and no aliases, anchors, merge keys or custom tags"}}
	}
	if decoder.Decode(&document) != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return invalid()
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return invalid()
	}
	count := 0
	value, err := yamlValue(document.Content[0], 0, &count)
	if err != nil {
		return invalid()
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return invalid()
	}
	return Decode(normalized)
}

var decimalInteger = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
var errYAMLInput = errors.New("unsupported_yaml_input")

func yamlValue(n *yaml.Node, depth int, count *int) (any, error) {
	*count++
	if depth > 30 || *count > 20000 || n.Anchor != "" || n.Kind == yaml.AliasNode {
		return nil, errYAMLInput
	}
	switch n.Kind {
	case yaml.MappingNode:
		if n.Tag != "!!map" || len(n.Content)%2 != 0 {
			return nil, errYAMLInput
		}
		out := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" || key.Value == "<<" {
				return nil, errYAMLInput
			}
			if _, exists := out[key.Value]; exists {
				return nil, errYAMLInput
			}
			value, err := yamlValue(n.Content[i+1], depth+1, count)
			if err != nil {
				return nil, err
			}
			out[key.Value] = value
		}
		return out, nil
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return nil, errYAMLInput
		}
		out := []any{}
		for _, child := range n.Content {
			value, err := yamlValue(child, depth+1, count)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str", "!!timestamp":
			return n.Value, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			switch strings.ToLower(n.Value) {
			case "true":
				return true, nil
			case "false":
				return false, nil
			}
		case "!!int":
			if decimalInteger.MatchString(n.Value) {
				return json.Number(n.Value), nil
			}
		case "!!float":
			if len(n.Value) > 512 {
				return nil, errYAMLInput
			}
			if i := strings.IndexAny(n.Value, "eE"); i >= 0 {
				exponent, e := strconv.Atoi(n.Value[i+1:])
				if e != nil || exponent > 1000 || exponent < -1000 {
					return nil, errYAMLInput
				}
			}
			if json.Valid([]byte(n.Value)) {
				if exact, ok := new(big.Rat).SetString(n.Value); ok && exact.IsInt() {
					return json.Number(exact.Num().String()), nil
				}
				var value any
				d := json.NewDecoder(strings.NewReader(n.Value))
				d.UseNumber()
				if d.Decode(&value) == nil {
					if number, ok := value.(json.Number); ok {
						return number, nil
					}
				}
			}
		}
	}
	return nil, errYAMLInput
}
