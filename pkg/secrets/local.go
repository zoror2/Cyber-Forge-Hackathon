package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Local stores AES-256-GCM ciphertext in Postgres. The key lives outside the DB.
type Local struct {
	Pool *pgxpool.Pool
	aead cipher.AEAD
}
type envelope struct {
	Value string `json:"value"`
	Host  string `json:"allowed_host"`
}

func NewLocal(pool *pgxpool.Pool, key string) (*Local, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("CONFIGBRIDGE_MASTER_KEY must be base64-encoded 32 random bytes")
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, ErrUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Local{pool, aead}, nil
}
func (l *Local) seal(name string, s Secret) ([]byte, error) {
	data, err := json.Marshal(envelope{s.Value, s.AllowedHost})
	if err != nil {
		return nil, ErrUnavailable
	}
	nonce := make([]byte, l.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, ErrUnavailable
	}
	return l.aead.Seal(nonce, nonce, data, []byte(name)), nil
}
func (l *Local) open(name string, data []byte) (Secret, error) {
	n := l.aead.NonceSize()
	if len(data) < n {
		return Secret{}, ErrUnavailable
	}
	clear, err := l.aead.Open(nil, data[:n], data[n:], []byte(name))
	if err != nil {
		return Secret{}, ErrUnavailable
	}
	var e envelope
	if json.Unmarshal(clear, &e) != nil {
		return Secret{}, ErrUnavailable
	}
	return Secret{e.Value, e.Host}, nil
}
func (l *Local) PutSecret(ctx context.Context, name string, s Secret) error {
	data, err := l.seal(name, s)
	if err != nil {
		return ErrUnavailable
	}
	_, err = l.Pool.Exec(ctx, `INSERT INTO credentials_values(name,ciphertext) VALUES($1,$2) ON CONFLICT(name) DO UPDATE SET ciphertext=excluded.ciphertext`, name, data)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
func (l *Local) GetSecret(ctx context.Context, name string) (Secret, error) {
	var data []byte
	if l.Pool.QueryRow(ctx, "SELECT ciphertext FROM credentials_values WHERE name=$1", name).Scan(&data) != nil {
		return Secret{}, ErrUnavailable
	}
	return l.open(name, data)
}
