package secrets

import (
	"bytes"
	"configbridge/internal/engine"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestPerTenantEncryptionAndSafeWrapper(t *testing.T) {
	keys := map[string]string{"tenant-a": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), "tenant-b": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))}
	l, e := NewLocal(nil, keys)
	if e != nil {
		t.Fatal(e)
	}
	value := "SYNTHETIC_SENTINEL_CREDENTIAL"
	raw, e := l.seal("tenant-a", "token", value, "api.example.com")
	if e != nil || bytes.Contains(raw, []byte(value)) {
		t.Fatal("encryption failed")
	}
	got, host, e := l.open("tenant-a", "token", string(raw))
	if e != nil || got != value || host != "api.example.com" {
		t.Fatal("roundtrip failed")
	}
	for _, pair := range [][2]string{{"tenant-b", "token"}, {"tenant-a", "other"}} {
		if _, _, e = l.open(pair[0], pair[1], string(raw)); e == nil {
			t.Fatal("cross-scope ciphertext accepted")
		}
	}
	raw[len(raw)-1] ^= 1
	if _, _, e = l.open("tenant-a", "token", string(raw)); e == nil {
		t.Fatal("tamper accepted")
	}
	s := engine.NewSecret(value, host)
	js, _ := json.Marshal(s)
	if strings.Contains(fmt.Sprintf("%v %+v %#v", s, s, s), value) || bytes.Contains(js, []byte(value)) {
		t.Fatal("secret wrapper leaks")
	}
	keys["tenant-b"] = keys["tenant-a"]
	if _, e = NewLocal(nil, keys); e == nil {
		t.Fatal("shared tenant key accepted")
	}
}
