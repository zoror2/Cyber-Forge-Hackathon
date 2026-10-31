// Package secrets implements Member A's tenant-aware engine.SecretStore. Values
// cross that boundary only inside engine.NewSecret's non-printable wrapper.
package secrets

import (
	"configbridge/internal/engine"
	"configbridge/internal/store"
	"configbridge/pkg/config"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"sort"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("secret_unavailable")
var ErrBinding = errors.New("secret_binding_is_immutable")
var ErrInput = errors.New("invalid_secret_input")

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
	TenantID     string    `json:"tenant_id"`
	Name         string    `json:"name"`
	ID           string    `json:"id"`
	Owner        string    `json:"owner"`
	CreatedBy    string    `json:"created_by"`
	RotatedBy    string    `json:"rotated_by"`
	AllowedHosts []string  `json:"allowed_hosts"`
	AllowedHost  string    `json:"allowed_host"`
	Backend      string    `json:"backend"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (s *Service) Put(ctx context.Context, tenant, name, value, host string) error {
	return s.PutCredential(ctx, store.Caller{Tenant: tenant, Actor: "system:provisioner"}, name, Input{Value: value, Host: host})
}

// Input is write-only. Ownership and credential IDs are never accepted from JSON.
type Input struct {
	Value  string            `json:"value,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
	Host   string            `json:"allowed_host,omitempty"`
	Hosts  []string          `json:"allowed_hosts,omitempty"`
}

func (in Input) Normalize() (map[string]string, []string, error) {
	if (in.Value != "") == (len(in.Fields) > 0) || (in.Host != "") == (len(in.Hosts) > 0) {
		return nil, nil, ErrInput
	}
	fields := map[string]string{}
	if in.Value != "" {
		fields[engine.DefaultField] = in.Value
	} else {
		for k, v := range in.Fields {
			fields[k] = v
		}
	}
	if len(fields) > 16 {
		return nil, nil, ErrInput
	}
	for k, v := range fields {
		if !config.ValidID(k) || v == "" || strings.ContainsAny(v, "\r\n") {
			return nil, nil, ErrInput
		}
	}
	raw, err := json.Marshal(fields)
	if err != nil || len(raw) > 32768 {
		return nil, nil, ErrInput
	}
	hosts := append([]string(nil), in.Hosts...)
	if in.Host != "" {
		hosts = []string{in.Host}
	}
	if len(hosts) > 8 {
		return nil, nil, ErrInput
	}
	sort.Strings(hosts)
	for i, h := range hosts {
		if !config.ValidHost(h) || (i > 0 && h == hosts[i-1]) {
			return nil, nil, ErrInput
		}
	}
	return fields, hosts, nil
}
func (s *Service) PutCredential(ctx context.Context, caller store.Caller, name string, in Input) error {
	tenant := caller.Tenant
	fields, hosts, e := in.Normalize()
	if e != nil || !config.ValidID(tenant) || !config.ValidID(name) || caller.Actor == "" || len(caller.Actor) > 200 {
		return ErrInput
	}
	raw, _ := json.Marshal(fields)
	// Backend envelopes authenticate this canonical host set together with values.
	bound := strings.Join(hosts, ",")
	e = s.Store.ForTenant(tenant).WithTx(ctx, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", s.Store.ForTenant(tenant).LockKey("secret", name)); e != nil {
			return e
		}
		var previous []string
		var backend string
		e := tx.QueryRow(ctx, "SELECT allowed_hosts,backend FROM credentials_meta WHERE tenant_id=$1 AND name=$2", tenant, name).Scan(&previous, &backend)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return ErrUnavailable
		}
		sort.Strings(previous)
		if e == nil && (strings.Join(previous, ",") != bound || backend != s.BackendName) {
			return ErrBinding
		}
		if e = s.Backend.Write(ctx, tenant, name, string(raw), bound); e != nil {
			return ErrUnavailable
		}
		_, e = tx.Exec(ctx, `INSERT INTO credentials_meta(tenant_id,name,allowed_host,allowed_hosts,backend,owner,created_by,rotated_by,secret_format)VALUES($1,$2,$3,$4,$5,$6,$6,$6,'fields_v1') ON CONFLICT(tenant_id,name) DO UPDATE SET updated_at=now(),rotated_by=excluded.rotated_by,secret_format='fields_v1'`, tenant, name, hosts[0], hosts, s.BackendName, caller.Actor)
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
	var hosts []string
	var backend, id, format string
	e := s.Store.ForTenant(tenant).WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT allowed_hosts,backend,credential_id,secret_format FROM credentials_meta WHERE tenant_id=$1 AND name=$2", tenant, name).Scan(&hosts, &backend, &id, &format)
	})
	if e != nil || backend != s.BackendName {
		return engine.Secret{}, ErrUnavailable
	}
	value, bound, e := s.Backend.Read(ctx, tenant, name)
	if e != nil || bound != strings.Join(hosts, ",") || value == "" {
		return engine.Secret{}, ErrUnavailable
	}
	fields := map[string]string{engine.DefaultField: value}
	if format == "fields_v1" {
		if json.Unmarshal([]byte(value), &fields) != nil || len(fields) == 0 {
			return engine.Secret{}, ErrUnavailable
		}
	}
	return engine.NewSecretFields(fields, hosts...).WithID(id), nil
}
func (s *Service) List(ctx context.Context, tenant string, limit, offset int) (out []Metadata, err error) {
	out = []Metadata{}
	err = s.Store.ForTenant(tenant).WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, "SELECT tenant_id,name,allowed_host,backend,created_at,updated_at,credential_id,owner,created_by,rotated_by,allowed_hosts FROM credentials_meta WHERE tenant_id=$1 ORDER BY name LIMIT $2 OFFSET $3", tenant, limit, offset)
		if e != nil {
			return ErrUnavailable
		}
		defer rows.Close()
		for rows.Next() {
			var m Metadata
			if e = rows.Scan(&m.TenantID, &m.Name, &m.AllowedHost, &m.Backend, &m.CreatedAt, &m.UpdatedAt, &m.ID, &m.Owner, &m.CreatedBy, &m.RotatedBy, &m.AllowedHosts); e != nil {
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
