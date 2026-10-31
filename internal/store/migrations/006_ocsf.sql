-- OCSF becomes the common schema. Every record is one OCSF event (payload),
-- whatever its class; the PRD-era users/devices/events tables are retired.
DROP TABLE users, devices, events;
CREATE TABLE ocsf_records(
 tenant_id text NOT NULL,
 source text NOT NULL,
 external_id text NOT NULL,
 class_uid integer NOT NULL,
 payload jsonb NOT NULL,
 fetched_at timestamptz NOT NULL,
 run_id text NOT NULL,
 PRIMARY KEY(tenant_id,source,external_id),
 FOREIGN KEY(tenant_id,run_id) REFERENCES runs(tenant_id,id)
);
CREATE INDEX ocsf_records_class ON ocsf_records(tenant_id,class_uid,source);
-- Records dropped by a config filter are counted, never silently lost.
ALTER TABLE runs ADD COLUMN skipped integer NOT NULL DEFAULT 0;

__RLS_POLICIES__
