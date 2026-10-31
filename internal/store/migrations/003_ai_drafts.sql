CREATE TABLE ai_usage(tenant_id text NOT NULL REFERENCES tenants,day date NOT NULL,calls integer NOT NULL CHECK(calls>=0),PRIMARY KEY(tenant_id,day));
CREATE TABLE ai_audit(tenant_id text NOT NULL REFERENCES tenants,id bigserial,request_id text NOT NULL,actor text NOT NULL,
 source_id text NOT NULL,source_hash text NOT NULL,provider text NOT NULL,model text NOT NULL,prompt_version text NOT NULL,
 outcome text NOT NULL,output_hash text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,id));
__RLS_POLICIES__
