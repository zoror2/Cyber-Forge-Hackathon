package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrSessionReuse = errors.New("refresh_token_reuse")

// Refreshed is the user state a rotated session is valid for.
type Refreshed struct {
	UserID  string
	Role    string
	Version int
}

func hashToken(t string) []byte { h := sha256.Sum256([]byte(t)); return h[:] }

// CreateSession stores a refresh token hash for a signed-in user.
func (s Scope) CreateSession(ctx context.Context, user string, version int, token string, ttl time.Duration) (id string, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "INSERT INTO iam_sessions(tenant_id,user_id,token_hash,user_version,expires_at)VALUES($1,$2,$3,$4,now()+make_interval(secs=>$5)) RETURNING id",
			s.Tenant, user, hashToken(token), version, ttl.Seconds()).Scan(&id)
	})
	return
}

// RotateSession swaps the presented refresh token for next. It fails if the
// session is revoked or expired, or the user was disabled, deleted or had
// their password/role changed since sign-in. Presenting the previous token
// (already rotated out) revokes the session: someone else holds a copy.
func (s Scope) RotateSession(ctx context.Context, id, presented, next string) (out Refreshed, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		var cur, prev []byte
		var sessVer, userVer int
		var active, live bool
		e := tx.QueryRow(ctx, `SELECT s.token_hash,s.prev_hash,s.user_version,s.revoked_at IS NULL AND s.expires_at>now(),u.id,u.role,u.token_version,u.active
   FROM iam_sessions s JOIN iam_users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id
   WHERE s.tenant_id=$1 AND s.id=$2 FOR UPDATE OF s`, s.Tenant, id).Scan(&cur, &prev, &sessVer, &live, &out.UserID, &out.Role, &userVer, &active)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		h := hashToken(presented)
		if prev != nil && subtle.ConstantTimeCompare(h, prev) == 1 {
			tx.Exec(ctx, "UPDATE iam_sessions SET revoked_at=now() WHERE tenant_id=$1 AND id=$2", s.Tenant, id)
			if c := tx.Commit(ctx); c != nil {
				return c
			}
			return ErrSessionReuse
		}
		if subtle.ConstantTimeCompare(h, cur) != 1 || !live || !active || sessVer != userVer {
			return ErrNotFound
		}
		out.Version = userVer
		_, e = tx.Exec(ctx, "UPDATE iam_sessions SET prev_hash=token_hash,token_hash=$3,last_used_at=now() WHERE tenant_id=$1 AND id=$2", s.Tenant, id, hashToken(next))
		return e
	})
	return
}

// RevokeSession ends one session (sign out).
func (s Scope) RevokeSession(ctx context.Context, id string) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE iam_sessions SET revoked_at=now() WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL", s.Tenant, id)
		return e
	})
}

// RevokeUserSessions ends every session of a user except keep (may be "").
func (s Scope) RevokeUserSessions(ctx context.Context, user, keep string) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE iam_sessions SET revoked_at=now() WHERE tenant_id=$1 AND user_id=$2 AND id<>$3 AND revoked_at IS NULL", s.Tenant, user, keep)
		return e
	})
}

// SessionLive is checked with each access token so sign-out is immediate.
func (s Scope) SessionLive(ctx context.Context, id string) (ok bool, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM iam_sessions WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL AND expires_at>now())", s.Tenant, id).Scan(&ok)
	})
	return
}
