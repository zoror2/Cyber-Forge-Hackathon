-- Public sign-up with a hard cap on total accounts (CB_SIGNUP_MAX_ACCOUNTS).
-- The cap also bounds cost: each account can create at most one KMS key.
-- A transaction-level advisory lock serializes public sign-ups so concurrent
-- requests cannot overshoot the cap. Operator-created accounts are uncapped
-- (they use iam_create_account directly).
CREATE FUNCTION __SCHEMA__.iam_create_open_account(t text,n text,e text,ph text,maxn integer)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF maxn IS NULL OR maxn < 1 THEN RAISE EXCEPTION 'signup cap required'; END IF;
 PERFORM pg_advisory_xact_lock(hashtext('configbridge:open-signup'));
 IF (SELECT count(*) FROM __SCHEMA__.tenants) >= maxn THEN
  RAISE EXCEPTION 'signup_closed' USING ERRCODE='53400';
 END IF;
 RETURN __SCHEMA__.iam_create_account(t,'',n,e,ph);
END $$;
REVOKE ALL ON FUNCTION __SCHEMA__.iam_create_open_account(text,text,text,text,integer) FROM PUBLIC;
