// Package jsonvalue reads decoded JSON using legacy dotted paths or explicit
// RFC 6901 JSON Pointers. Pointers distinguish literal dots from object nesting.
package jsonvalue

import (
	"strconv"
	"strings"
)

// Tokens accepts JSON string pointers, not URI-fragment pointers or JSONPath.
// Empty paths address the root. Dotted paths retain their existing behavior.
func Tokens(path string) ([]string, bool) {
	if path == "" {
		return nil, true
	}
	if !strings.HasPrefix(path, "/") {
		return strings.Split(path, "."), true
	}
	parts := strings.Split(path[1:], "/")
	for i, part := range parts {
		var out strings.Builder
		for j := 0; j < len(part); j++ {
			if part[j] != '~' {
				out.WriteByte(part[j])
				continue
			}
			j++
			if j >= len(part) {
				return nil, false
			}
			switch part[j] {
			case '0':
				out.WriteByte('~')
			case '1':
				out.WriteByte('/')
			default:
				return nil, false
			}
		}
		parts[i] = out.String()
	}
	return parts, true
}

func Path(value any, path string) (any, bool) {
	parts, ok := Tokens(path)
	if !ok {
		return nil, false
	}
	pointer := strings.HasPrefix(path, "/")
	for _, part := range parts {
		switch v := value.(type) {
		case map[string]any:
			value, ok = v[part]
			if !ok {
				return nil, false
			}
		case []any:
			// JSON Pointer permits only canonical, non-negative array indexes.
			if pointer && (part == "" || (len(part) > 1 && part[0] == '0') || strings.Trim(part, "0123456789") != "") {
				return nil, false
			}
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || n >= len(v) {
				return nil, false
			}
			value = v[n]
		default:
			return nil, false
		}
	}
	return value, true
}
