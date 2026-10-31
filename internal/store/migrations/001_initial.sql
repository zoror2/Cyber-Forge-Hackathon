CREATE TABLE tenants(tenant_id text PRIMARY KEY, kms_key_id text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX tenant_kms_keys ON tenants(kms_key_id) WHERE kms_key_id<>'';
CREATE TABLE api_keys(key_hash bytea PRIMARY KEY,tenant_id text NOT NULL REFERENCES tenants,active boolean NOT NULL DEFAULT true);
CREATE TABLE configs(
 tenant_id text NOT NULL REFERENCES tenants,id text NOT NULL,version integer NOT NULL,
 status text NOT NULL CHECK(status IN('draft','approved','live')),body jsonb NOT NULL,config_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,id,version)
);
CREATE UNIQUE INDEX one_live_config ON configs(tenant_id,id) WHERE status='live';
CREATE TABLE credentials_meta(tenant_id text NOT NULL REFERENCES tenants,name text NOT NULL,allowed_host text NOT NULL,backend text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,name));
CREATE TABLE credentials_values(tenant_id text NOT NULL REFERENCES tenants,name text NOT NULL,ciphertext bytea NOT NULL,PRIMARY KEY(tenant_id,name));
CREATE TABLE runs(
 tenant_id text NOT NULL,id text NOT NULL,connector text NOT NULL,config_version integer NOT NULL,config_hash text NOT NULL,
 mode text NOT NULL CHECK(mode IN('live','test')),started_at timestamptz NOT NULL,ended_at timestamptz,
 outcome text NOT NULL CHECK(outcome IN('running','success','completed_with_errors','failed','incomplete','interrupted')),
 pages integer NOT NULL DEFAULT 0,attempts integer NOT NULL DEFAULT 0,received integer NOT NULL DEFAULT 0,accepted integer NOT NULL DEFAULT 0,quarantined integer NOT NULL DEFAULT 0,error text NOT NULL DEFAULT '',
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,connector,config_version) REFERENCES configs(tenant_id,id,version)
);
CREATE INDEX runs_connector_time ON runs(tenant_id,connector,started_at DESC);
CREATE TABLE users(tenant_id text NOT NULL,source text NOT NULL,external_id text NOT NULL,payload jsonb NOT NULL,fetched_at timestamptz NOT NULL,run_id text NOT NULL,PRIMARY KEY(tenant_id,source,external_id),FOREIGN KEY(tenant_id,run_id) REFERENCES runs(tenant_id,id));
CREATE TABLE devices(LIKE users INCLUDING ALL);
ALTER TABLE devices ADD CONSTRAINT devices_run_fk FOREIGN KEY(tenant_id,run_id) REFERENCES runs(tenant_id,id);
CREATE TABLE events(LIKE users INCLUDING ALL);
ALTER TABLE events ADD CONSTRAINT events_run_fk FOREIGN KEY(tenant_id,run_id) REFERENCES runs(tenant_id,id);
CREATE TABLE quarantine(tenant_id text NOT NULL,id bigserial,run_id text NOT NULL,source text NOT NULL,page integer NOT NULL,record_index integer NOT NULL,field text NOT NULL,reason text NOT NULL,PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,run_id) REFERENCES runs(tenant_id,id));
CREATE INDEX quarantine_source ON quarantine(tenant_id,source,id DESC);
CREATE TABLE sync_state(tenant_id text NOT NULL,connector text NOT NULL,last_success timestamptz,next_due timestamptz NOT NULL DEFAULT now(),watermark jsonb,PRIMARY KEY(tenant_id,connector),FOREIGN KEY(tenant_id) REFERENCES tenants);

-- Tenant context is transaction-local. RLS is forced even for table owners;
-- the trusted migration owner has an explicit policy for provisioning/functions.
-- The runtime role is checked separately and may never be that owner.
__RLS_POLICIES__

CREATE FUNCTION __SCHEMA__.authenticate_api_key(h bytea) RETURNS TABLE(tenant_id text,key_hash bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS
 'SELECT a.tenant_id,a.key_hash FROM __SCHEMA__.api_keys a WHERE a.key_hash=h AND a.active=true';
CREATE FUNCTION __SCHEMA__.due_connectors() RETURNS TABLE(tenant_id text,id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS
 'SELECT tenant_id,id FROM (SELECT c.tenant_id,c.id,s.next_due,row_number() OVER(PARTITION BY c.tenant_id ORDER BY s.next_due,c.id) AS rn FROM __SCHEMA__.configs c JOIN __SCHEMA__.sync_state s ON s.tenant_id=c.tenant_id AND s.connector=c.id WHERE c.status=''live'' AND c.body->''schedule''->>''enabled''=''true'' AND s.next_due<=now()) d WHERE rn=1 ORDER BY next_due,tenant_id LIMIT 100';
CREATE FUNCTION __SCHEMA__.running_connectors() RETURNS TABLE(tenant_id text,id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS
 'SELECT DISTINCT tenant_id,connector FROM __SCHEMA__.runs WHERE outcome=''running''';
REVOKE ALL ON FUNCTION __SCHEMA__.authenticate_api_key(bytea),__SCHEMA__.due_connectors(),__SCHEMA__.running_connectors() FROM PUBLIC;
