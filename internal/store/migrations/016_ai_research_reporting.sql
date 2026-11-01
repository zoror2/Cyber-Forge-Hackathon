-- Successful vendor research is a successful AI request in usage reports.
CREATE OR REPLACE FUNCTION __SCHEMA__.ai_consumption_report(p_from date,p_to date,p_customer text,p_limit integer,p_offset integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE result jsonb;
BEGIN
 IF p_from IS NULL OR p_to IS NULL OR p_customer IS NULL OR length(p_customer)>64
  OR p_limit IS NULL OR p_offset IS NULL OR p_to-p_from NOT BETWEEN 0 AND 89
  OR p_limit NOT BETWEEN 1 AND 100 OR p_offset NOT BETWEEN 0 AND 100000 THEN
  RAISE EXCEPTION 'invalid_ai_report_range' USING ERRCODE='22023';
 END IF;
 WITH base AS MATERIALIZED (
  SELECT * FROM __SCHEMA__.ai_requests r
  WHERE r.created_at>=p_from::timestamp AT TIME ZONE 'UTC'
   AND r.created_at<(p_to+1)::timestamp AT TIME ZONE 'UTC'
   AND (p_customer='' OR r.tenant_id=p_customer)
 ), totals AS (
  SELECT count(request_id) requests,coalesce(sum(total_tokens),0) reported_tokens,
   coalesce(sum(reserved_tokens) FILTER(WHERE total_tokens IS NULL),0) unreported_reserved_tokens,
   coalesce(sum(input_tokens),0) input_tokens,coalesce(sum(output_tokens),0) output_tokens,
   count(*) FILTER(WHERE finished_at IS NOT NULL AND outcome NOT IN('drafted','explained','researched')) failed_requests,
   count(*) FILTER(WHERE finished_at IS NULL) pending_requests,
   count(*) FILTER(WHERE finished_at IS NOT NULL AND total_tokens IS NULL) unknown_requests FROM base
 ), customers AS (
  SELECT t.tenant_id customer,count(b.request_id) requests,coalesce(sum(b.total_tokens),0) reported_tokens,
   coalesce(sum(b.reserved_tokens) FILTER(WHERE b.total_tokens IS NULL AND b.request_id IS NOT NULL),0) unreported_reserved_tokens,
   coalesce(sum(b.input_tokens),0) input_tokens,coalesce(sum(b.output_tokens),0) output_tokens,
   count(*) FILTER(WHERE b.finished_at IS NOT NULL AND b.outcome NOT IN('drafted','explained','researched')) failed_requests,
   count(b.request_id) FILTER(WHERE b.finished_at IS NULL) pending_requests,
   count(*) FILTER(WHERE b.finished_at IS NOT NULL AND b.total_tokens IS NULL) unknown_requests
  FROM __SCHEMA__.tenants t LEFT JOIN base b ON b.tenant_id=t.tenant_id
  WHERE p_customer='' OR t.tenant_id=p_customer GROUP BY t.tenant_id
 ), daily AS (
  SELECT d.day::date::text AS "day",count(b.request_id) requests,coalesce(sum(b.total_tokens),0) reported_tokens,
   coalesce(sum(b.reserved_tokens) FILTER(WHERE b.total_tokens IS NULL AND b.request_id IS NOT NULL),0) unreported_reserved_tokens
  FROM generate_series(p_from::timestamp,p_to::timestamp,interval '1 day') d(day)
  LEFT JOIN base b ON (b.created_at AT TIME ZONE 'UTC')::date=d.day::date GROUP BY d.day
 ), breakdown AS (
  SELECT provider,model,operation,count(*) requests,coalesce(sum(total_tokens),0) reported_tokens,
   coalesce(sum(reserved_tokens) FILTER(WHERE total_tokens IS NULL),0) unreported_reserved_tokens
  FROM base GROUP BY provider,model,operation
 ), requests AS (
  SELECT tenant_id customer,request_id,operation,provider,model,outcome,reserved_tokens,
   input_tokens,output_tokens,total_tokens,created_at,finished_at,
   CASE WHEN finished_at IS NOT NULL THEN greatest(0,round(extract(epoch FROM finished_at-created_at)*1000))::bigint END duration_ms
  FROM base ORDER BY created_at DESC,request_id,tenant_id LIMIT p_limit OFFSET p_offset
 )
 SELECT jsonb_build_object(
  'from',p_from::text,'to',p_to::text,'timezone','UTC','summary',(SELECT to_jsonb(x) FROM totals x),
  'customers',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.reported_tokens DESC,x.customer) FROM
   (SELECT * FROM customers ORDER BY reported_tokens DESC,customer LIMIT 200) x),'[]'::jsonb),
  'customer_count',(SELECT count(*) FROM customers),
  'daily',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.day) FROM daily x),'[]'::jsonb),
  'breakdown',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.provider,x.model,x.operation) FROM
   (SELECT * FROM breakdown ORDER BY provider,model,operation LIMIT 200) x),'[]'::jsonb),
  'requests',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.created_at DESC,x.request_id,x.customer) FROM requests x),'[]'::jsonb)
 ) INTO result;
 RETURN result;
END $$;
