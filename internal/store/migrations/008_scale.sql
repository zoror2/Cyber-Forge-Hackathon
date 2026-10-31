-- Load-test fixes.
-- 1. GET /runs without a connector filter did a parallel seq scan + sort over
--    all runs (15 cores of Postgres at 200k runs). This index serves it.
CREATE INDEX runs_tenant_time ON __SCHEMA__.runs(tenant_id,started_at DESC,id);
-- 2. The scheduler took one due connector per tenant per tick (1 run/s per
--    tenant). Now up to 4 per tenant per tick, matching the runner's per-tenant
--    concurrency. Privileges are kept by CREATE OR REPLACE.
CREATE OR REPLACE FUNCTION __SCHEMA__.due_connectors() RETURNS TABLE(tenant_id text,id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS
 'SELECT tenant_id,id FROM (SELECT c.tenant_id,c.id,s.next_due,row_number() OVER(PARTITION BY c.tenant_id ORDER BY s.next_due,c.id) AS rn FROM __SCHEMA__.configs c JOIN __SCHEMA__.sync_state s ON s.tenant_id=c.tenant_id AND s.connector=c.id WHERE c.status=''live'' AND c.body->''schedule''->>''enabled''=''true'' AND s.next_due<=now()) d WHERE rn<=4 ORDER BY rn,next_due,tenant_id LIMIT 200';
