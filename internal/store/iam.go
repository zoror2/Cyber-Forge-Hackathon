package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrExists    = errors.New("already_exists")
	ErrLastAdmin = errors.New("last_admin")
	ErrKeyQuota  = errors.New("key_quota")
)

// MaxKeysPerUser mirrors AWS IAM: two access keys, so one can be rotated.
const MaxKeysPerUser = 2

type User struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Active      bool       `json:"active"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
	Version     int        `json:"-"`
}
type Key struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	Active     bool       `json:"active"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}
type Login struct {
	ID, Hash, Role string
	Active         bool
	Version        int
}

func unique(e error) bool {
	var pg *pgconn.PgError
	return errors.As(e, &pg) && pg.Code == "23505"
}

// CreateAccount makes a tenant and its first admin in one transaction.
func (s *Store) CreateAccount(ctx context.Context, tenant, kms, name, email, hash string) (string, error) {
	var id string
	e := s.Pool.QueryRow(ctx, "SELECT iam_create_account($1,$2,$3,$4,$5)", tenant, kms, name, email, hash).Scan(&id)
	if unique(e) {
		return "", ErrExists
	}
	return id, e
}

// ErrSignupClosed: public sign-up reached its account cap.
var ErrSignupClosed = errors.New("signup_closed")

// CreateOpenAccount is public self sign-up: like CreateAccount, with no KMS
// key (created on first credential) and refused once maxAccounts exist.
func (s *Store) CreateOpenAccount(ctx context.Context, tenant, name, email, hash string, maxAccounts int) (string, error) {
	var id string
	e := s.Pool.QueryRow(ctx, "SELECT iam_create_open_account($1,$2,$3,$4,$5)", tenant, name, email, hash, maxAccounts).Scan(&id)
	var pg *pgconn.PgError
	if errors.As(e, &pg) && pg.Code == "53400" {
		return "", ErrSignupClosed
	}
	if unique(e) {
		return "", ErrExists
	}
	return id, e
}
func (s *Store) LoginLookup(ctx context.Context, tenant, email string) (Login, error) {
	var l Login
	e := s.Pool.QueryRow(ctx, "SELECT id,password_hash,active,role,token_version FROM iam_login_lookup($1,$2)", tenant, email).Scan(&l.ID, &l.Hash, &l.Active, &l.Role, &l.Version)
	if errors.Is(e, pgx.ErrNoRows) {
		return l, ErrNotFound
	}
	return l, e
}

const userCols = "id,name,email,role,active,created_by,created_at,last_login_at,token_version"

func scanUser(r pgx.Row) (u User, e error) {
	e = r.Scan(&u.ID, &u.Name, &u.Email, &u.Role, &u.Active, &u.CreatedBy, &u.CreatedAt, &u.LastLoginAt, &u.Version)
	if errors.Is(e, pgx.ErrNoRows) {
		e = ErrNotFound
	}
	return
}
func (s Scope) User(ctx context.Context, id string) (u User, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		u, err = scanUser(tx.QueryRow(ctx, "SELECT "+userCols+" FROM iam_users WHERE tenant_id=$1 AND id=$2", s.Tenant, id))
		return err
	})
	return
}
func (s Scope) Users(ctx context.Context, limit, offset int) (out []User, err error) {
	out = []User{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, "SELECT "+userCols+" FROM iam_users WHERE tenant_id=$1 ORDER BY created_at,id LIMIT $2 OFFSET $3", s.Tenant, limit, offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			u, e := scanUser(rows)
			if e != nil {
				return e
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	return
}
func (s Scope) CreateUser(ctx context.Context, name, email, role, hash, by string) (u User, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		u, err = scanUser(tx.QueryRow(ctx, "INSERT INTO iam_users(tenant_id,name,email,role,password_hash,created_by)VALUES($1,$2,$3,$4,$5,$6) RETURNING "+userCols, s.Tenant, name, email, role, hash, by))
		if unique(err) {
			return ErrExists
		}
		return err
	})
	return
}

// guardAdmins runs a change and refuses it if it leaves an account that had an
// active admin user with none. Admin rows are locked so two concurrent
// demotions can't both pass.
func (s Scope) guardAdmins(ctx context.Context, change func(pgx.Tx) error) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		var before int
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM (SELECT 1 FROM iam_users WHERE tenant_id=$1 AND role='admin' AND active FOR UPDATE) a", s.Tenant).Scan(&before); e != nil {
			return e
		}
		if e := change(tx); e != nil {
			return e
		}
		var after int
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM iam_users WHERE tenant_id=$1 AND role='admin' AND active", s.Tenant).Scan(&after); e != nil {
			return e
		}
		if before > 0 && after == 0 {
			return ErrLastAdmin
		}
		return nil
	})
}

// UpdateUser changes role/name/active. Deactivating or changing the role ends
// existing sessions (token_version bump); keys stop working with the user.
func (s Scope) UpdateUser(ctx context.Context, id string, name, role *string, active *bool) error {
	return s.guardAdmins(ctx, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `UPDATE iam_users SET name=COALESCE($3,name),role=COALESCE($4,role),active=COALESCE($5,active),
  token_version=token_version+CASE WHEN ($4::text IS NOT NULL AND $4<>role) OR ($5::bool IS NOT NULL AND $5<>active) THEN 1 ELSE 0 END
  WHERE tenant_id=$1 AND id=$2`, s.Tenant, id, name, role, active)
		if e == nil && tag.RowsAffected() != 1 {
			e = ErrNotFound
		}
		return e
	})
}
func (s Scope) DeleteUser(ctx context.Context, id string) error {
	return s.guardAdmins(ctx, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, "DELETE FROM iam_users WHERE tenant_id=$1 AND id=$2", s.Tenant, id)
		if e == nil && tag.RowsAffected() != 1 {
			e = ErrNotFound
		}
		return e
	})
}

// SetPassword stores a new hash and signs the user out everywhere.
func (s Scope) SetPassword(ctx context.Context, id, hash string) (version int, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx, "UPDATE iam_users SET password_hash=$3,token_version=token_version+1 WHERE tenant_id=$1 AND id=$2 RETURNING token_version", s.Tenant, id, hash).Scan(&version)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	return
}
func (s Scope) PasswordHash(ctx context.Context, id string) (hash string, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx, "SELECT password_hash FROM iam_users WHERE tenant_id=$1 AND id=$2 AND active", s.Tenant, id).Scan(&hash)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	return
}
func (s Scope) TouchLogin(ctx context.Context, id string) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE iam_users SET last_login_at=now() WHERE tenant_id=$1 AND id=$2", s.Tenant, id)
		return e
	})
}

const keyCols = "principal_id,COALESCE(user_id,''),name,active,created_at,last_used_at"

func (s Scope) Keys(ctx context.Context, user string) (out []Key, err error) {
	out = []Key{}
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, "SELECT "+keyCols+" FROM api_keys WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at", s.Tenant, user)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var k Key
			if e = rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Active, &k.CreatedAt, &k.LastUsedAt); e != nil {
				return e
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return
}

// CreateKey stores only the SHA-256 of a new key for a user (max 2 per user).
func (s Scope) CreateKey(ctx context.Context, user, name, secret string) (k Key, err error) {
	hash := sha256.Sum256([]byte(secret))
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		var n int
		// lock the owner row: two concurrent creates can't both pass the quota
		if e := tx.QueryRow(ctx, "SELECT 1 FROM iam_users WHERE tenant_id=$1 AND id=$2 FOR UPDATE", s.Tenant, user).Scan(&n); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return e
		}
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM api_keys WHERE tenant_id=$1 AND user_id=$2", s.Tenant, user).Scan(&n); e != nil {
			return e
		}
		if n >= MaxKeysPerUser {
			return ErrKeyQuota
		}
		return tx.QueryRow(ctx, "INSERT INTO api_keys(key_hash,tenant_id,user_id,name)VALUES($1,$2,$3,$4) RETURNING "+keyCols, hash[:], s.Tenant, user, name).
			Scan(&k.ID, &k.UserID, &k.Name, &k.Active, &k.CreatedAt, &k.LastUsedAt)
	})
	return
}

// Key returns one user-owned key (root keys are not managed here).
func (s Scope) Key(ctx context.Context, id string) (k Key, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx, "SELECT "+keyCols+" FROM api_keys WHERE tenant_id=$1 AND principal_id=$2 AND user_id IS NOT NULL", s.Tenant, id).
			Scan(&k.ID, &k.UserID, &k.Name, &k.Active, &k.CreatedAt, &k.LastUsedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	return
}
func (s Scope) SetKeyActive(ctx context.Context, id string, active bool) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, "UPDATE api_keys SET active=$3 WHERE tenant_id=$1 AND principal_id=$2 AND user_id IS NOT NULL", s.Tenant, id, active)
		if e == nil && tag.RowsAffected() != 1 {
			e = ErrNotFound
		}
		return e
	})
}
func (s Scope) DeleteKey(ctx context.Context, id string) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, "DELETE FROM api_keys WHERE tenant_id=$1 AND principal_id=$2 AND user_id IS NOT NULL", s.Tenant, id)
		if e == nil && tag.RowsAffected() != 1 {
			e = ErrNotFound
		}
		return e
	})
}

// RootKeyActive is checked on every request of a session opened with the
// account root key, so revoking that key ends the session too.
func (s Scope) RootKeyActive(ctx context.Context, id string) (ok bool, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM api_keys WHERE tenant_id=$1 AND principal_id=$2 AND user_id IS NULL AND active)", s.Tenant, id).Scan(&ok)
	})
	return
}

// TouchKey records last use at most once a minute per key (cheap, best effort).
func (s Scope) TouchKey(ctx context.Context, id string) {
	s.WithTx(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE api_keys SET last_used_at=now() WHERE tenant_id=$1 AND principal_id=$2 AND (last_used_at IS NULL OR last_used_at<now()-interval '1 minute')", s.Tenant, id)
		return e
	})
}
