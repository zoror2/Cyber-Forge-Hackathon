package engine

// This file defines how secrets (API keys, passwords, client secrets) travel
// inside the engine. Goal: a secret value can never end up in a log line, an
// error message, a JSON response or a debug print, even by accident.

import (
	"context"
	"log/slog"
)

// Secret is one credential (one or more named fields) plus the exact hosts it
// may be sent to. Most secrets have one field ("value"); vendors that need
// several parts use named fields, e.g. client_id + client_secret, or
// key_id + key (Cortex), or username + password.
//
// Why the fields are hidden inside a function ("reveal"):
// Go's fmt package can print unexported struct fields using reflection, which
// would bypass our String() method below. A function value, however, prints
// only as a memory address (e.g. 0xc000123456), never its contents. So even
// `fmt.Printf("%+v", someStructContainingASecret)` cannot leak the value.
type Secret struct {
	reveal func(field string) (string, bool) // returns one field's value; only engine code calls it
	hosts  []string                          // the only hosts this secret may be sent to (exact match)
	id     string                            // credential ID (NOT secret): links errors and data to the credential record
}

// DefaultField is the field name used by single-value secrets (NewSecret).
const DefaultField = "value"

// NewSecret is how a secrets backend (Member B) hands a single-value secret
// (an API key, a token) to the engine. It is stored as field "value".
//
// allowedHosts is usually ONE host ("api.crowdstrike.com"). Use more only when
// a vendor really needs it, e.g. OAuth with a separate token host:
//
//	NewSecret(v, "auth.app.wiz.io", "api.us17.app.wiz.io")
//
// Wildcards are refused when the secret is used.
func NewSecret(value string, allowedHosts ...string) Secret {
	return NewSecretFields(map[string]string{DefaultField: value}, allowedHosts...)
}

// NewSecretFields hands the engine a multi-part secret:
//
//	NewSecretFields(map[string]string{"client_id": id, "client_secret": s}, "api.crowdstrike.com")
//
// The map is copied, so the caller can't change (or wipe) it later.
func NewSecretFields(fields map[string]string, allowedHosts ...string) Secret {
	own := make(map[string]string, len(fields))
	for k, v := range fields {
		own[k] = v
	}
	hosts := append([]string(nil), allowedHosts...) // own copy: caller can't change it later
	return Secret{reveal: func(f string) (string, bool) { v, ok := own[f]; return v, ok }, hosts: hosts}
}

// field returns one field's value. Lowercase (unexported), so only code inside
// the engine package can call it: auth.go uses it to build headers.
func (s Secret) field(name string) (string, bool) {
	if s.reveal == nil { // zero-value Secret{}: no fields at all
		return "", false
	}
	return s.reveal(name)
}

// value returns the "value" field ("" if missing): single-value secrets.
func (s Secret) value() string {
	v, _ := s.field(DefaultField)
	return v
}

// WithID returns a copy of the secret tagged with its credential ID, the
// stable, non-secret ID of the credential record (owner, label, status...).
// Member B's store sets it; the engine puts it on every auth error and log
// line so the platform knows WHICH credential (and so which person) to fix.
func (s Secret) WithID(id string) Secret { s.id = id; return s }

// ID returns the credential ID ("" if the store didn't set one).
func (s Secret) ID() string { return s.id }

// AllowedHosts returns a copy of the bound hosts (safe to log or display).
func (s Secret) AllowedHosts() []string { return append([]string(nil), s.hosts...) }

// Every way of turning a Secret into text returns "[redacted]":
func (Secret) String() string               { return "[redacted]" }                   // fmt %v, %s, Println
func (Secret) GoString() string             { return "[redacted]" }                   // fmt %#v
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }    // encoding/json
func (Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }      // text encoders, map keys
func (Secret) LogValue() slog.Value         { return slog.StringValue("[redacted]") } // structured logs (slog)

// SecretStore is the contract between the engine and Member B's secrets backend.
//
// The tenant is an explicit parameter (not hidden in ctx) so the compiler
// forces every caller to supply it. Implementations must never return another
// tenant's secret, even when two tenants use the same secret name.
type SecretStore interface {
	Get(ctx context.Context, tenantID, name string) (Secret, error)
}
