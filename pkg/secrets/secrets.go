// Package secrets implements Member A's tenant-aware engine.SecretStore. Values
// cross that boundary only inside engine.NewSecret's non-printable wrapper.
package secrets

import (
	"configbridge/internal/engine"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

var ErrUnavailable = errors.New("secret_unavailable")
var ErrBinding = errors.New("secret_binding_is_immutable")

type Backend interface {
	Read(context.Context, string, string) (string, string, error)
	Write(context.Context, string, string, string, string) error
}
type Service struct {
	Store       *store.Store
	Backend     Backend
	BackendName string
}
type Metadata struct {
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	AllowedHost string    `json:"allowed_host"`
	Backend     string    `json:"backend"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (s *Service) Put(ctx context.Context, tenant, name, value, host string) error {
	if !config.ValidID(tenant) || !config.ValidID(name) || !config.ValidHost(host) || value == "" || len(value) > 32768 {
		return errors.New("invalid_secret_input")
	}
	e := s.Store.ForTenant(tenant).WithTx(ctx, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", s.Store.ForTenant(tenant).LockKey("secret", name)); e != nil {
			return e
		}
		var previous, backend string
		e := tx.QueryRow(ctx, "SELECT allowed_host,backend FROM credentials_meta WHERE tenant_id=$1 AND name=$2", tenant, name).Scan(&previous, &backend)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return ErrUnavailable
		}
		if e == nil && (previous != host || backend != s.BackendName) {
			return ErrBinding
		}
		if e = s.Backend.Write(ctx, tenant, name, value, host); e != nil {
			return ErrUnavailable
		}
		_, e = tx.Exec(ctx, "INSERT INTO credentials_meta(tenant_id,name,allowed_host,backend)VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,name) DO UPDATE SET updated_at=now()", tenant, name, host, s.BackendName)
		return e
	})
	if errors.Is(e, ErrBinding) {
		return ErrBinding
	}
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Service) Get(ctx context.Context, tenant, name string) (engine.Secret, error) {
	if !config.ValidID(tenant) || !config.ValidID(name) {
		return engine.Secret{}, ErrUnavailable
	}
	var host, backend string
	e := s.Store.ForTenant(tenant).WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT allowed_host,backend FROM credentials_meta WHERE tenant_id=$1 AND name=$2", tenant, name).Scan(&host, &backend)
	})
	if e != nil || backend != s.BackendName {
		return engine.Secret{}, ErrUnavailable
	}
	value, bound, e := s.Backend.Read(ctx, tenant, name)
	if e != nil || bound != host || value == "" {
		return engine.Secret{}, ErrUnavailable
	}
	return engine.NewSecret(value, bound), nil
}
func (s *Service) List(ctx context.Context, tenant string, limit, offset int) (out []Metadata, err error) {
	out = []Metadata{}
	err = s.Store.ForTenant(tenant).WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, "SELECT tenant_id,name,allowed_host,backend,created_at,updated_at FROM credentials_meta WHERE tenant_id=$1 ORDER BY name LIMIT $2 OFFSET $3", tenant, limit, offset)
		if e != nil {
			return ErrUnavailable
		}
		defer rows.Close()
		for rows.Next() {
			var m Metadata
			if e = rows.Scan(&m.TenantID, &m.Name, &m.AllowedHost, &m.Backend, &m.CreatedAt, &m.UpdatedAt); e != nil {
				return ErrUnavailable
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	if err != nil {
		err = ErrUnavailable
	}
	return
}

var _ engine.SecretStore = (*Service)(nil)
