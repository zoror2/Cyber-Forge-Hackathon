CREATE TABLE siem_snapshots(
 tenant_id text NOT NULL REFERENCES tenants,connector text NOT NULL,generation text NOT NULL,
 window_start timestamptz NOT NULL,window_end timestamptz NOT NULL,run_sample_capped boolean NOT NULL,
 PRIMARY KEY(tenant_id,connector));
CREATE TABLE siem_findings(
 tenant_id text NOT NULL,connector text NOT NULL,id text NOT NULL,generation text NOT NULL,
 rule text NOT NULL,severity text NOT NULL,category text NOT NULL,count bigint NOT NULL CHECK(count>0),observed_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,connector) REFERENCES siem_snapshots(tenant_id,connector));
CREATE INDEX siem_findings_connector ON siem_findings(tenant_id,connector,generation);
CREATE TABLE ai_requests(
 tenant_id text NOT NULL REFERENCES tenants,request_id text NOT NULL,operation text NOT NULL CHECK(operation IN('config_draft','siem_explanation')),
 provider text NOT NULL,model text NOT NULL,outcome text NOT NULL DEFAULT 'reserved',reserved_tokens bigint NOT NULL CHECK(reserved_tokens>0),
 input_tokens bigint,output_tokens bigint,total_tokens bigint,created_at timestamptz NOT NULL DEFAULT now(),finished_at timestamptz,
 PRIMARY KEY(tenant_id,request_id),CHECK((input_tokens IS NULL AND output_tokens IS NULL AND total_tokens IS NULL) OR
 (input_tokens>=0 AND output_tokens>=0 AND total_tokens=input_tokens+output_tokens AND total_tokens>0)));
CREATE INDEX ai_requests_day ON ai_requests(tenant_id,created_at);
__RLS_POLICIES__
