# Live source evidence (PRD §15)

Redacted: no secrets, no raw responses. Runs through the unchanged engine via the API
(`POST /configs` → `/validate` → `/activate` → `/connectors/{id}/test` → `/run`), production egress rules
(public HTTPS only, no redirects), local Docker stack.

| # | Source | Config | Config hash (sha256) | Run (UTC) | Endpoint category | Auth | Paging | Pages | Received / accepted / quarantined | Outcome |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | CISA KEV | `configs/cisa_kev.json` rev 1 | `23d7e7ca…3f988d` | 2026-10-31 11:35:00 | vulnerability feed (catalog 2026.10.30) | none | none (single document) | 1 | 1766 / 1766 / 0 | success |
| 1b | CISA KEV re-run | same | same | 2026-10-31 11:35:07 | same | none | none | 1 | 1766 / 1766 / 0 | success: `events` still 1766 rows (upsert, no duplicates) |
| 2 | GitHub REST | pending | | | | bearer | Link header | ≥2 required | | |
| 3 | NVD CVE or Jira | pending | | | | api_key / basic | offset | ≥2 required | | |

Notes
- KEV has no severity field; `severity` is mapped to the constant `unknown` instead of being inferred.
- `timestamp` comes from `dateAdded` (date precision, recorded as `timestamp_precision: date`).
- The test run (`mode: test`) sampled 100 records and wrote nothing.
