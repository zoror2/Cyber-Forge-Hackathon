-- Progress already lives under forced tenant RLS in sync_state.watermark.
-- Keep each run's exact query bounds and checkpoint decision for inspection.
ALTER TABLE runs ADD COLUMN incremental jsonb;
