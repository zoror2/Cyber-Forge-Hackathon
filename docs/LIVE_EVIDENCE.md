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
| 1c | CISA KEV as **OCSF** Vulnerability Finding | `configs/cisa_kev.json` rev 3 | `d99abbfe…5e8ece` | 2026-10-31 13:15:59 | same | none | none | 1 | 1766 / 1766 / 0 | success: `ocsf_records` class 2002 = 1766 rows |
| 1d | KEV OCSF re-run | same | same | 2026-10-31 13:16:01 | same | none | none | 1 | 1766 / 1766 / 0 | success: still 1766 (upsert) |
| 1e | KEV **filter demo** (`knownRansomwareCampaignUse = Known`) | `cisa_kev_ransomware` rev 1 | `5e7cbb2d…fb4aac` | 2026-10-31 13:16:17 | same | none | none | 1 | 1766 / 361 / 0, **1405 skipped** | success: matches the 361 ransomware-linked entries in the catalog |
| 2c | GitHub as **OCSF** User Inventory Info | `configs/github_members.json` rev 2 | `9c950aed…ef3cd2` | 2026-10-31 13:16:02 | same | bearer | Link header | 4 | 36 / 36 / 0 | success: class 5003 = 36 rows |
| 2d | GitHub OCSF re-run | same | same | 2026-10-31 13:16:04 | same | bearer | Link header | 4 | 36 / 36 / 0 | success: upsert |
| 3 | NVD CVE API 2.0 (`hasKev`) as **OCSF** Vulnerability Finding | `configs/nvd_kev_cves.json` rev 2 | `480e5597…e8eae6` | 2026-10-31 14:08:54 | CVE database, KEV subset (CVSS severity) | api_key (header `apiKey`, free NVD key) | offset (`startIndex`/`resultsPerPage`, 200) | 9 | 1765 / 1765 / 0 | success, 9.2 s; severity: 628 Critical, 916 High, 205 Medium, 10 Low, 6 Unknown (no CVSS 3.1) |
| 3b | NVD re-run | same | same | 2026-10-31 14:09:03 | same | api_key | offset | 9 | 1765 / 1765 / 0 | success: `ocsf_records` nvd_kev_cves still 1765 (upsert) |

Notes
- Rows 1/1b/2/2b ran on the earlier User/Device/Event schema; 1c onwards are OCSF 1.9.0 (`metadata.version`).
- KEV has no severity field; `severity_id` stays 0 (Unknown) instead of being inferred.
- OCSF `time` comes from `dateAdded` (midnight UTC, epoch ms); product and ransomware use go to `unmapped`.
- The test run (`mode: test`) sampled 100 records and wrote nothing.
- GitHub: `email`, `status`, `last_login` are not in the members endpoint and are stored as `null`, not inferred (PRD §14).
- Secret check after the GitHub runs: 0 occurrences of a GitHub token prefix in API logs, `users` / `ocsf_records`, `runs` or `configs`;
  `credentials_values` holds only AES-GCM ciphertext (188 bytes, no plaintext prefix). `GET /secrets` returns metadata only.
- NVD: key stored as tenant secret `nvd` bound to `services.nvd.nist.gov` (138-byte AES-GCM ciphertext). After the runs:
  0 UUID-shaped strings (NVD key format) in API logs, `ocsf_records` (nvd), `runs.error` or `configs`.
- NVD supplies the CVSS severity KEV lacks: same 1765 CVE IDs, joinable on `vulnerabilities[0].cve.uid`.
