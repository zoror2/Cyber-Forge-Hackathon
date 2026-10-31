CREATE TABLE IF NOT EXISTS configs (
 id text NOT NULL, version integer NOT NULL, status text NOT NULL CHECK(status IN ('draft','approved','live')),
 body jsonb NOT NULL, config_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(id,version)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_live_config ON configs(id) WHERE status='live';
CREATE TABLE IF NOT EXISTS credentials_meta (
 name text PRIMARY KEY, allowed_host text NOT NULL, backend text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS credentials_values (
 name text PRIMARY KEY, ciphertext bytea NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
 id text PRIMARY KEY, connector text NOT NULL, config_version integer NOT NULL, config_hash text NOT NULL,
 mode text NOT NULL CHECK(mode IN ('fixture','live')), started_at timestamptz NOT NULL, ended_at timestamptz,
 outcome text NOT NULL CHECK(outcome IN ('running','success','completed_with_errors','failed','incomplete','interrupted')),
 pages integer NOT NULL DEFAULT 0, attempts integer NOT NULL DEFAULT 0, received integer NOT NULL DEFAULT 0,
 accepted integer NOT NULL DEFAULT 0, quarantined integer NOT NULL DEFAULT 0, error text NOT NULL DEFAULT '',
 FOREIGN KEY(connector,config_version) REFERENCES configs(id,version)
);
CREATE INDEX IF NOT EXISTS runs_connector_time ON runs(connector,started_at DESC);
CREATE TABLE IF NOT EXISTS users (
 source text NOT NULL, external_id text NOT NULL, payload jsonb NOT NULL, fetched_at timestamptz NOT NULL,
 run_id text NOT NULL REFERENCES runs(id), PRIMARY KEY(source,external_id)
);
CREATE TABLE IF NOT EXISTS devices (LIKE users INCLUDING ALL);
CREATE TABLE IF NOT EXISTS events (LIKE users INCLUDING ALL);
ALTER TABLE devices ADD CONSTRAINT devices_run_fk FOREIGN KEY(run_id) REFERENCES runs(id);
ALTER TABLE events ADD CONSTRAINT events_run_fk FOREIGN KEY(run_id) REFERENCES runs(id);
CREATE TABLE IF NOT EXISTS quarantine (
 id bigserial PRIMARY KEY, run_id text NOT NULL REFERENCES runs(id), source text NOT NULL,
 record_index integer NOT NULL, field text NOT NULL, reason text NOT NULL
);
CREATE INDEX IF NOT EXISTS quarantine_source ON quarantine(source,id DESC);
CREATE TABLE IF NOT EXISTS sync_state (
 connector text PRIMARY KEY, last_success timestamptz, next_due timestamptz NOT NULL DEFAULT now(),
 watermark jsonb
);
