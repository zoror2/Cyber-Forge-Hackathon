package engine

// This file defines how secrets (API keys, passwords, client secrets) travel
// inside the engine. Goal: a secret value can never end up in a log line, an
// error message, a JSON response or a debug print, even by accident.

import (
	"context"
	"log/slog"
)

// Secret is a credential value plus the ONE host it may be sent to.
//
// Why the value is hidden inside a function ("reveal"):
// Go's fmt package can print unexported struct fields using reflection, which
// would bypass our String() method below. A function value, however, prints
// only as a memory address (e.g. 0xc000123456), never its contents. So even
// `fmt.Printf("%+v", someStructContainingASecret)` cannot leak the value.
type Secret struct {
	reveal func() string // returns the real value; only engine code calls it
	host   string        // the only host this secret may be sent to
}

// NewSecret is how a secrets backend (Member B) hands a secret to the engine.
// The value is captured inside the closure and is not stored in a field.
func NewSecret(value, allowedHost string) Secret {
	return Secret{reveal: func() string { return value }, host: allowedHost}
}

// value returns the real secret. It is lowercase (unexported), so only code
// inside the engine package can call it: auth.go uses it to build headers.
func (s Secret) value() string {
	if s.reveal == nil { // zero-value Secret{}: no value at all
		return ""
	}
	return s.reveal()
}

// AllowedHost returns the host this secret is bound to (safe to log).
func (s Secret) AllowedHost() string { return s.host }

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
