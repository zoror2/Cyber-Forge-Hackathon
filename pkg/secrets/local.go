package secrets

import (
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
)

// Local is development-only. Each tenant must have a distinct key; there is no
// global fallback. Production uses per-tenant KMS-backed AWS Secrets Manager.
type Local struct {
	Store *store.Store
	keys  map[string]cipher.AEAD
}
type envelope struct {
	Value  string `json:"value"`
	Host   string `json:"allowed_host"`
	Tenant string `json:"tenant_id"`
}

func NewLocal(s *store.Store, keys map[string]string) (*Local, error) {
	if len(keys) == 0 {
		return nil, errors.New("development tenant keyring is required")
	}
	out := &Local{Store: s, keys: map[string]cipher.AEAD{}}
	seen := map[string]bool{}
	for tenant, key := range keys {
		raw, e := base64.StdEncoding.DecodeString(key)
		if !config.ValidID(tenant) || e != nil || len(raw) != 32 || seen[string(raw)] {
			return nil, errors.New("each development tenant requires a distinct base64 32-byte key")
		}
		seen[string(raw)] = true
		block, e := aes.NewCipher(raw)
		if e != nil {
			return nil, ErrUnavailable
		}
		aead, e := cipher.NewGCM(block)
		if e != nil {
			return nil, ErrUnavailable
		}
		out.keys[tenant] = aead
	}
	return out, nil
}
func (l *Local) seal(tenant, name, value, host string) ([]byte, error) {
	aead := l.keys[tenant]
	if aead == nil {
		return nil, ErrUnavailable
	}
	raw, e := json.Marshal(envelope{value, host, tenant})
	if e != nil {
		return nil, ErrUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, ErrUnavailable
	}
	return aead.Seal(nonce, nonce, raw, []byte(tenant+"/"+name)), nil
}
func (l *Local) open(tenant, name, raw string) (string, string, error) {
	aead := l.keys[tenant]
	data := []byte(raw)
	if aead == nil || len(data) < aead.NonceSize() {
		return "", "", ErrUnavailable
	}
	n := aead.NonceSize()
	clear, e := aead.Open(nil, data[:n], data[n:], []byte(tenant+"/"+name))
	if e != nil {
		return "", "", ErrUnavailable
	}
	var env envelope
	if json.Unmarshal(clear, &env) != nil || env.Tenant != tenant {
		return "", "", ErrUnavailable
	}
	return env.Value, env.Host, nil
}
func (l *Local) Write(ctx context.Context, tenant, name, value, host string) error {
	raw, e := l.seal(tenant, name, value, host)
	if e != nil {
		return ErrUnavailable
	}
	e = l.Store.ForTenant(tenant).WithTx(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO credentials_values(tenant_id,name,ciphertext)VALUES($1,$2,$3) ON CONFLICT(tenant_id,name) DO UPDATE SET ciphertext=excluded.ciphertext", tenant, name, raw)
		return e
	})
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
func (l *Local) Read(ctx context.Context, tenant, name string) (string, string, error) {
	var raw []byte
	e := l.Store.ForTenant(tenant).WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT ciphertext FROM credentials_values WHERE tenant_id=$1 AND name=$2", tenant, name).Scan(&raw)
	})
	if e != nil {
		return "", "", ErrUnavailable
	}
	return l.open(tenant, name, string(raw))
}
