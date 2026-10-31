package config

import (
	"os"
	"testing"
)

// Configs are untrusted jury/customer input. Parsing must remain bounded and
// must never panic on malformed JSON, unexpected types or unusual nesting.
func FuzzDecodeUntrustedConfig(f *testing.F) {
	if b, err := os.ReadFile("../../tests/testdata/jury/users_config.json"); err == nil {
		f.Add(b)
	}
	for _, seed := range []string{`{}`, `null`, `{"version":1,"version":2}`, `{"request":{"method":[]}}`, `[[[[[[]]]]]]`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) { Decode(b) })
}
