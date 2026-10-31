-- Console sessions: the refresh-token side. The access token is a short JWT;
-- the refresh token is opaque, stored here only as a SHA-256 hash, and rotated
-- on every use. prev_hash remembers the last rotated-out token: if it is ever
-- presented again someone kept a copy, so the whole session is revoked.
CREATE TABLE iam_sessions(
 tenant_id text NOT NULL,
 id text NOT NULL DEFAULT gen_random_uuid()::text,
 user_id text NOT NULL,
 token_hash bytea NOT NULL,
 prev_hash bytea,
 user_version integer NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 last_used_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES iam_users(tenant_id,id) ON DELETE CASCADE);
CREATE INDEX iam_sessions_user ON iam_sessions(tenant_id,user_id) WHERE revoked_at IS NULL;
__RLS_POLICIES__
