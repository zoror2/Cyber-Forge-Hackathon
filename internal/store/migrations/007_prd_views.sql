-- PRD "common schema (minimum)" as read-only views over the OCSF store.
-- OCSF stays the source of truth; these present the PRD's exact field names.
-- security_invoker=true: the caller's row-level security on ocsf_records
-- applies, so a tenant only ever sees its own rows through a view.

-- OCSF times are epoch milliseconds; unmapped values may be ISO strings.
-- Anything unparseable becomes NULL instead of failing the whole query.
CREATE FUNCTION __SCHEMA__.cb_ts(v jsonb) RETURNS timestamptz
LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
 IF v IS NULL THEN RETURN NULL; END IF;
 IF jsonb_typeof(v)='number' THEN RETURN to_timestamp((v#>>'{}')::numeric/1000); END IF;
 IF jsonb_typeof(v)='string' AND (v#>>'{}') ~ '^\d{4}-\d{2}-\d{2}' THEN RETURN (v#>>'{}')::timestamptz; END IF;
 RETURN NULL;
EXCEPTION WHEN others THEN RETURN NULL;
END $$;

CREATE VIEW __SCHEMA__.users WITH (security_invoker=true) AS
SELECT tenant_id,
 payload#>>'{user,uid}' AS id,
 COALESCE(payload#>>'{user,full_name}',payload#>>'{user,display_name}',payload#>>'{user,name}') AS name,
 payload#>>'{user,email_addr}' AS email,
 COALESCE(payload#>>'{unmapped,status}',
  CASE payload#>>'{user,account,is_disabled}' WHEN 'true' THEN 'disabled' WHEN 'false' THEN 'active' END) AS status,
 source,
 __SCHEMA__.cb_ts(payload#>'{unmapped,last_login}') AS last_login,
 fetched_at
FROM __SCHEMA__.ocsf_records WHERE class_uid=5003;

CREATE VIEW __SCHEMA__.devices WITH (security_invoker=true) AS
SELECT tenant_id,
 payload#>>'{device,uid}' AS id,
 payload#>>'{device,hostname}' AS hostname,
 payload#>>'{device,ip}' AS ip,
 payload#>>'{device,os,name}' AS os,
 COALESCE(payload#>>'{device,owner,email_addr}',payload#>>'{device,owner,name}') AS owner,
 source,
 __SCHEMA__.cb_ts(payload#>'{device,last_seen_time}') AS last_seen,
 fetched_at
FROM __SCHEMA__.ocsf_records WHERE class_uid=5001;

-- Event/Alert: every finding/activity class (everything that is not an inventory).
CREATE VIEW __SCHEMA__.events WITH (security_invoker=true) AS
SELECT tenant_id,
 COALESCE(payload#>>'{finding_info,uid}',payload#>>'{metadata,uid}',external_id) AS id,
 payload->>'class_name' AS type,
 payload->>'severity' AS severity,
 __SCHEMA__.cb_ts(payload->'time') AS "timestamp",
 COALESCE(payload#>>'{finding_info,desc}',payload->>'message',payload#>>'{finding_info,title}') AS description,
 source,
 fetched_at
FROM __SCHEMA__.ocsf_records WHERE class_uid NOT IN (5001,5003);
