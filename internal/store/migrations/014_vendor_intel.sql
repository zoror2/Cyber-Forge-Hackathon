-- Vendor ownership map: AI acquisition and attack research share the daily AI budget.
ALTER TABLE ai_requests DROP CONSTRAINT IF EXISTS ai_requests_operation_check;
ALTER TABLE ai_requests ADD CONSTRAINT ai_requests_operation_check CHECK(operation IN('config_draft','siem_explanation','vendor_intel'));
