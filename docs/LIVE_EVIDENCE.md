# Live source evidence (PRD §15)

Redacted: no secrets, no raw responses. Runs through the unchanged engine via the API
(`POST /configs` → `/validate` → `/activate` → `/connectors/{id}/test` → `/run`), production egress rules
(public HTTPS only, no redirects), local Docker stack.

| # | Source | Config | Config hash (sha256) | Run (UTC) | Endpoint category | Auth | Paging | Pages | Received / accepted / quarantined | Outcome |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | CISA KEV | `configs/cisa_kev.json` rev 1 | `23d7e7ca…3f988d` | 2026-10-31 11:35:00 | vulnerability feed (catalog 2026.10.30) | none | none (single document) | 1 | 1766 / 1766 / 0 | success |
| 1b | CISA KEV re-run | same | same | 2026-10-31 11:35:07 | same | none | none | 1 | 1766 / 1766 / 0 | success: `events` still 1766 rows (upsert, no duplicates) |
| 2 | GitHub REST | `configs/github_members.json` rev 1 | `d854adb4…edc5c489` | 2026-10-31 12:26:37 | org public members (OWASP) | bearer (fine-grained, read-only, 7-day token) | Link header, `per_page=10` | 4 | 36 / 36 / 0 | success |
| 2b | GitHub re-run | same | same | 2026-10-31 12:26:39 | same | bearer | Link header | 4 | 36 / 36 / 0 | success: upsert, no duplicates |
| 3 | NVD CVE or Jira | pending | | | | api_key / basic | offset | ≥2 required | | |

Notes
- KEV has no severity field; `severity` is mapped to the constant `unknown` instead of being inferred.
- `timestamp` comes from `dateAdded` (date precision, recorded as `timestamp_precision: date`).
- The test run (`mode: test`) sampled 100 records and wrote nothing.
- GitHub: `email`, `status`, `last_login` are not in the members endpoint and are stored as `null`, not inferred (PRD §14).
- Secret check after the GitHub runs: 0 occurrences of a GitHub token prefix in API logs, `users`, `runs` or `configs`;
  `credentials_values` holds only AES-GCM ciphertext (188 bytes, no plaintext prefix). `GET /secrets` returns metadata only.
