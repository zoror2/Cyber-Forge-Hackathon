CREATE TABLE alert_state(
 tenant_id text NOT NULL REFERENCES tenants,connector text NOT NULL,failure_streak integer NOT NULL DEFAULT 0,
 episode bigint NOT NULL DEFAULT 0,notified_episode bigint NOT NULL DEFAULT 0,last_queued_at timestamptz,
 PRIMARY KEY(tenant_id,connector));
CREATE TABLE alert_outbox(
 tenant_id text NOT NULL REFERENCES tenants,id text NOT NULL DEFAULT gen_random_uuid()::text,connector text NOT NULL,
 run_id text NOT NULL,episode bigint NOT NULL,failure_count integer NOT NULL,error_category text NOT NULL,outcome text NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN('pending','sending','sent','abandoned','cancelled')),
 attempts integer NOT NULL DEFAULT 0,next_attempt_at timestamptz NOT NULL DEFAULT now(),lease_until timestamptz,lease_token text,
 created_at timestamptz NOT NULL DEFAULT now(),sent_at timestamptz,last_delivery_error text NOT NULL DEFAULT '',
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,connector,episode),FOREIGN KEY(tenant_id,run_id) REFERENCES runs(tenant_id,id));
CREATE INDEX alert_due ON alert_outbox(next_attempt_at) WHERE status IN('pending','sending');
__RLS_POLICIES__
CREATE FUNCTION __SCHEMA__.due_alerts() RETURNS TABLE(tenant_id text,id text,connector text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS
 'SELECT tenant_id,id,connector FROM (SELECT a.tenant_id,a.id,a.connector,a.next_attempt_at,row_number() OVER(PARTITION BY a.tenant_id ORDER BY a.next_attempt_at,a.id) rn FROM __SCHEMA__.alert_outbox a WHERE (a.status=''pending'' AND a.next_attempt_at<=now()) OR (a.status=''sending'' AND a.lease_until<=now())) q WHERE rn=1 ORDER BY next_attempt_at,tenant_id LIMIT 20';
REVOKE ALL ON FUNCTION __SCHEMA__.due_alerts() FROM PUBLIC;
