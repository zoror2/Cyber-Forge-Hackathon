-- IAM-style identities inside an account (tenant), modelled on AWS IAM:
--   account      = tenant (created by sign-up or a platform operator, never by a tenant)
--   user         = a person: name, email (login), one role, password
--   role         = managed policy (admin/editor/operator/viewer), enforced in the API
--   access key   = api_keys row owned by a user; inherits that user's role.
--                  user_id NULL = the account's root key from bootstrap (admin).
CREATE TABLE iam_users(
 tenant_id text NOT NULL REFERENCES tenants,
 id text NOT NULL DEFAULT gen_random_uuid()::text,
 name text NOT NULL CHECK(length(btrim(name)) BETWEEN 1 AND 100),
 email text NOT NULL CHECK(email=lower(btrim(email)) AND length(email) BETWEEN 3 AND 254),
 role text NOT NULL CHECK(role IN('admin','editor','operator','viewer')),
 password_hash text NOT NULL,
 active boolean NOT NULL DEFAULT true,
 -- bumped on password change/reset, deactivation and "sign out everywhere":
 -- every session token carrying an older version stops working at once
 token_version integer NOT NULL DEFAULT 1,
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 last_login_at timestamptz,
 PRIMARY KEY(tenant_id,id),
 UNIQUE(tenant_id,email));
__RLS_POLICIES__

ALTER TABLE api_keys ADD COLUMN user_id text;
ALTER TABLE api_keys ADD COLUMN name text NOT NULL DEFAULT '';
ALTER TABLE api_keys ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE api_keys ADD COLUMN last_used_at timestamptz;
ALTER TABLE api_keys ADD FOREIGN KEY(tenant_id,user_id) REFERENCES iam_users(tenant_id,id) ON DELETE CASCADE;
CREATE INDEX api_keys_user ON api_keys(tenant_id,user_id);

-- Key lookup before any tenant is known. A key works only while it and its
-- owner are active; the role always comes from the owner (root key = admin).
CREATE FUNCTION __SCHEMA__.authenticate_api_key_user(h bytea)
RETURNS TABLE(tenant_id text,key_hash bytea,principal_id text,user_id text,role text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS
 'SELECT a.tenant_id,a.key_hash,a.principal_id,a.user_id,COALESCE(u.role,''admin'')
  FROM __SCHEMA__.api_keys a LEFT JOIN __SCHEMA__.iam_users u ON u.tenant_id=a.tenant_id AND u.id=a.user_id
  WHERE a.key_hash=h AND a.active AND (a.user_id IS NULL OR u.active)';

-- Password sign-in before any tenant is known: one row for (account, email).
CREATE FUNCTION __SCHEMA__.iam_login_lookup(t text,e text)
RETURNS TABLE(id text,password_hash text,active boolean,role text,token_version integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS
 'SELECT u.id,u.password_hash,u.active,u.role,u.token_version FROM __SCHEMA__.iam_users u WHERE u.tenant_id=t AND u.email=e';

-- Account creation: a new tenant plus its first admin, atomically. Refuses an
-- existing account id (no takeover). Callers are gated in the API.
CREATE FUNCTION __SCHEMA__.iam_create_account(t text,kms text,n text,e text,ph text)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE uid text;
BEGIN
 INSERT INTO __SCHEMA__.tenants(tenant_id,kms_key_id) VALUES(t,kms) ON CONFLICT(tenant_id) DO NOTHING;
 IF NOT FOUND THEN RAISE EXCEPTION 'account_exists' USING ERRCODE='23505'; END IF;
 INSERT INTO __SCHEMA__.iam_users(tenant_id,name,email,role,password_hash,created_by)
  VALUES(t,n,e,'admin',ph,'signup') RETURNING id INTO uid;
 RETURN uid;
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.authenticate_api_key_user(bytea),__SCHEMA__.iam_login_lookup(text,text),
 __SCHEMA__.iam_create_account(text,text,text,text,text) FROM PUBLIC;
