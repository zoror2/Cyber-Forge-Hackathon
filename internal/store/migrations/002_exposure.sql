-- Stable opaque IDs identify API-key principals; they are not human identities.
ALTER TABLE api_keys ADD COLUMN principal_id text NOT NULL DEFAULT gen_random_uuid()::text UNIQUE;
ALTER TABLE credentials_meta ADD COLUMN credential_id text NOT NULL DEFAULT gen_random_uuid()::text;
CREATE UNIQUE INDEX credential_ids ON credentials_meta(tenant_id,credential_id);
ALTER TABLE credentials_meta ADD COLUMN owner text NOT NULL DEFAULT 'legacy:unknown';
ALTER TABLE credentials_meta ADD COLUMN created_by text NOT NULL DEFAULT 'legacy:unknown';
ALTER TABLE credentials_meta ADD COLUMN rotated_by text NOT NULL DEFAULT 'legacy:unknown';
ALTER TABLE credentials_meta ADD COLUMN allowed_hosts text[] NOT NULL DEFAULT '{}';
UPDATE credentials_meta SET allowed_hosts=ARRAY[allowed_host];
ALTER TABLE credentials_meta ADD COLUMN secret_format text NOT NULL DEFAULT 'legacy' CHECK(secret_format IN('legacy','fields_v1'));

CREATE FUNCTION __SCHEMA__.authenticate_api_key_identity(h bytea)
RETURNS TABLE(tenant_id text,key_hash bytea,principal_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS
 'SELECT a.tenant_id,a.key_hash,a.principal_id FROM __SCHEMA__.api_keys a WHERE a.key_hash=h AND a.active=true';
REVOKE ALL ON FUNCTION __SCHEMA__.authenticate_api_key_identity(bytea) FROM PUBLIC;

-- Global reference data, maintained through reviewed migrations, never tenant writes.
-- Exact vendor/product pairs only. These are vendor associations, not version matches.
CREATE TABLE vendor_aliases(kev_vendor text NOT NULL,kev_product text NOT NULL,vendor text NOT NULL,
 PRIMARY KEY(kev_vendor,kev_product), CHECK(kev_vendor=lower(btrim(kev_vendor))),CHECK(kev_product=lower(btrim(kev_product))));
INSERT INTO vendor_aliases VALUES
 ('atlassian','confluence data center and server','Atlassian'),
 ('atlassian','jira server and data center','Atlassian'),
 ('github','enterprise server','GitHub'),
 ('ivanti','endpoint manager (epm)','Ivanti'),
 ('ivanti','cloud services appliance','Ivanti'),
 ('ivanti','cloud services appliance (csa)','Ivanti');
CREATE INDEX kev_vendor_product ON events(tenant_id,lower(btrim(payload->>'vendor')),lower(btrim(payload->>'product')))
 WHERE payload->>'type'='known_exploited_vulnerability';
