// Package secrets supplies Member A's host-bound secret interface. Never format
// or return Value through logs, errors, run results, or HTTP responses.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zoror2/Cyber-Forge-Hackathon/pkg/config"
)

var ErrUnavailable = errors.New("secret_unavailable")
var ErrBinding = errors.New("secret_host_binding_cannot_change")

type Secret struct {
	Value       string `json:"-"`
	AllowedHost string `json:"allowed_host"`
}

func (s Secret) String() string                { return "[redacted secret]" }
func (s Secret) GoString() string              { return "[redacted secret]" }
func (s Secret) Format(f fmt.State, verb rune) { fmt.Fprint(f, "[redacted secret]") }

type Reader interface {
	GetSecret(context.Context, string) (Secret, error)
}
type Backend interface {
	GetSecret(context.Context, string) (Secret, error)
	PutSecret(context.Context, string, Secret) error
}
type Metadata struct {
	Name        string    `json:"name"`
	AllowedHost string    `json:"allowed_host"`
	Backend     string    `json:"backend"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
type Service struct {
	Pool        *pgxpool.Pool
	Backend     Backend
	BackendName string
}

func (s *Service) Put(ctx context.Context, name, value, host string) error {
	if !config.ValidID(name) || !config.ValidHost(host) || len(value) == 0 || len(value) > 32768 {
		return errors.New("invalid_secret_input")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "secret:"+name); err != nil {
		return ErrUnavailable
	}
	var previous, backend string
	err = tx.QueryRow(ctx, "SELECT allowed_host,backend FROM credentials_meta WHERE name=$1", name).Scan(&previous, &backend)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ErrUnavailable
	}
	if err == nil && (previous != host || backend != s.BackendName) {
		return ErrBinding
	}
	if err = s.Backend.PutSecret(ctx, name, Secret{Value: value, AllowedHost: host}); err != nil {
		return ErrUnavailable
	}
	_, err = tx.Exec(ctx, `INSERT INTO credentials_meta(name,allowed_host,backend) VALUES($1,$2,$3) ON CONFLICT(name) DO UPDATE SET updated_at=now()`, name, host, s.BackendName)
	if err != nil {
		return ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Service) GetSecret(ctx context.Context, name string) (Secret, error) {
	if !config.ValidID(name) {
		return Secret{}, ErrUnavailable
	}
	var host, backend string
	if s.Pool.QueryRow(ctx, "SELECT allowed_host,backend FROM credentials_meta WHERE name=$1", name).Scan(&host, &backend) != nil || backend != s.BackendName {
		return Secret{}, ErrUnavailable
	}
	secret, err := s.Backend.GetSecret(ctx, name)
	if err != nil || secret.AllowedHost != host {
		return Secret{}, ErrUnavailable
	}
	return secret, nil
}
func (s *Service) List(ctx context.Context, limit, offset int) ([]Metadata, error) {
	rows, err := s.Pool.Query(ctx, "SELECT name,allowed_host,backend,created_at,updated_at FROM credentials_meta ORDER BY name LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	out := []Metadata{}
	for rows.Next() {
		var m Metadata
		if rows.Scan(&m.Name, &m.AllowedHost, &m.Backend, &m.CreatedAt, &m.UpdatedAt) != nil {
			return nil, ErrUnavailable
		}
		out = append(out, m)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}
