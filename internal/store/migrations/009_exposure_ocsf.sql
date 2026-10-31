-- KEV exposure (migration 2) read the PRD-era events table, retired by OCSF (6).
-- KEV rows are now OCSF Vulnerability Findings (class 2002); vendor/product live
-- at vulnerabilities[0].vendor_name and unmapped.product.
CREATE INDEX kev_vendor_product ON __SCHEMA__.ocsf_records(tenant_id,lower(btrim(payload#>>'{vulnerabilities,0,vendor_name}')),lower(btrim(payload#>>'{unmapped,product}')))
 WHERE class_uid=2002;
