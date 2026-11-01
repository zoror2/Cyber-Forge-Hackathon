-- Binds the CALLER's tenant (transaction-local app.tenant_id) to its first KMS
-- key, exactly once: an existing key is never replaced. Returns the key now
-- bound, so a racing writer learns it lost and discards the key it created.
CREATE FUNCTION __SCHEMA__.bind_tenant_kms_key(k text)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE t text := current_setting('app.tenant_id', true); bound text;
BEGIN
 IF t IS NULL OR t = '' OR k IS NULL OR k = '' THEN RAISE EXCEPTION 'tenant and key required'; END IF;
 UPDATE __SCHEMA__.tenants SET kms_key_id = k WHERE tenant_id = t AND kms_key_id = '' RETURNING kms_key_id INTO bound;
 IF bound IS NULL THEN SELECT kms_key_id INTO bound FROM __SCHEMA__.tenants WHERE tenant_id = t; END IF;
 RETURN bound;
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.bind_tenant_kms_key(text) FROM PUBLIC;
