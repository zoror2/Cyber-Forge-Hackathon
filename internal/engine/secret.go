package engine

import (
	"context"
	"log/slog"
)

// Secret is a credential value plus the one host it may be sent to.
//
// The value lives inside a closure, so even when a Secret sits in an
// unexported struct field (where fmt bypasses String methods) printing shows
// only a function address. Every other printing path shows "[redacted]".
type Secret struct {
	reveal func() string
	host   string
}

// NewSecret is used by secret backends (Member B) to hand a secret to the engine.
func NewSecret(value, allowedHost string) Secret {
	return Secret{reveal: func() string { return value }, host: allowedHost}
}

func (s Secret) value() string {
	if s.reveal == nil {
		return ""
	}
	return s.reveal()
}

func (s Secret) AllowedHost() string        { return s.host }
func (Secret) String() string               { return "[redacted]" }
func (Secret) GoString() string             { return "[redacted]" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }
func (Secret) LogValue() slog.Value         { return slog.StringValue("[redacted]") }

// SecretStore is the contract with Member B's secrets backend.
type SecretStore interface {
	Get(ctx context.Context, name string) (Secret, error)
}
