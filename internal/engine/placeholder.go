package engine

// This file fills {{secret.<field>}} placeholders in static auth headers.
//
// It is deliberately tiny: no template engine, no expressions, no functions.
// The ONLY thing it can do is paste a named secret field into a string. That
// keeps config from ever becoming code (no loops, no file access, no escapes).

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// placeholder matches {{secret.<field>}} with optional spaces inside the braces.
// Field names are lowercase letters, digits and "_", max 32 characters.
var placeholder = regexp.MustCompile(`\{\{\s*secret\.([a-z0-9_]{1,32})\s*\}\}`)

// secretPlaceholders returns the secret field names a header value uses, and
// an error if it contains anything that LOOKS like a placeholder but isn't a
// valid {{secret.<field>}} (e.g. a typo or another namespace), so mistakes
// fail at validation instead of sending "{{secrt.key}}" to the vendor.
func secretPlaceholders(v string) ([]string, error) {
	var fields []string
	for _, m := range placeholder.FindAllStringSubmatch(v, -1) {
		fields = append(fields, m[1])
	}
	rest := placeholder.ReplaceAllString(v, "")
	if strings.Contains(rest, "{{") || strings.Contains(rest, "}}") {
		return nil, errors.New("only {{secret.<field>}} placeholders are allowed")
	}
	if strings.ContainsAny(rest, "\r\n\x00") {
		return nil, errors.New("control characters are not allowed")
	}
	return fields, nil
}

// renderSecret replaces every {{secret.<field>}} in v with that field's value.
//
// Fails (without revealing anything) if:
//   - a field is missing from the secret: names the field, never a value
//   - the resulting value contains CR, LF or NUL: a secret like "x\r\nEvil: 1"
//     would otherwise inject an extra HTTP header
func renderSecret(v string, s Secret) (string, error) {
	if _, err := secretPlaceholders(v); err != nil {
		return "", err
	}
	var missing string
	out := placeholder.ReplaceAllStringFunc(v, func(m string) string {
		name := placeholder.FindStringSubmatch(m)[1]
		val, ok := s.field(name)
		if !ok && missing == "" {
			missing = name
		}
		return val
	})
	if missing != "" {
		return "", fmt.Errorf("secret has no field %q", missing)
	}
	if strings.ContainsAny(out, "\r\n\x00") {
		return "", errors.New("secret value contains control characters")
	}
	return out, nil
}
