# End-to-end test plan — real sources only

Manual run by a human tester. No mock vendor, no synthetic data: every record
comes from CISA, NVD or GitHub. Each expectation below is derived from the code
(file references given), not from other docs.

Extra real-source configs used here live in `configs/e2e/` and all pass
`config.Decode` (the same validator as `POST /configs`).

## What cannot be proven against a real vendor (be honest with the jury)

| Item | Why | Evidence instead |
|---|---|---|
| FR-8 429 + Retry-After | No real API returns 429 on demand without abusing it. GitHub/NVD rate limits mostly answer **403**, which the engine classifies as `auth_failed` and does not retry (`internal/engine/engine.go` `retryDelay`, `once`). | `go test ./internal/engine -run "TestRateLimit" -v` |
| SIEM `high_severity_events`, `authentication_failures` | Need Detection Finding (2004) or Authentication (3002) records. No free real source here produces them. | Explain the rule; show `connection_health` live instead. |
| SIEM `kev_catalog_entries` | Counts KEV records whose OCSF `time` (= `dateAdded`) is inside the **last 24 h** (`internal/store/siem.go`). On 1 Nov 2026 the newest KEV entry is dated 30 Oct, so the result is `no_findings` and **no AI call**, unless CISA adds an entry that day. | Show the honest `no_findings` answer. |
| `/exposure` | Matches live connector `vendor` labels against KEV `vendorProject`. KEV has **0** GitHub entries, so the result is empty for the sources here. | Explain it; non-empty only with a Microsoft/Sophos/Elastic connector. |
| B-1 on NVD | NVD `lastModified` has no timezone; `pkg/incremental/window.go` `CheckRow` requires RFC3339 → every row would be quarantined. | B-1 runs on GitHub commits instead (below). |
| Reviewed AI profiles (GitHub/NVD/CISA presets) | `internal/ai/reviewed.go` `reviewedDraft` **always returns the hardcoded config**; the model's proposal is only compared (`reviewed_profile` vs `reviewed_profile_fallback`) and then discarded. This is not AI drafting. | Real AI drafting = the "Another dataset: use public API documentation" flow (A-2). |

---

## 0. Setup (once)

### 0.1 Accounts and keys you need
- GitHub personal access token (fine-grained, public read is enough; repo read for B-1 on a private repo).
- NVD API key: https://nvd.nist.gov/developers/request-an-api-key
- Gmail address with 2-step verification + a 16-character **App password** (for B-4).
- Docker Desktop running (only for OpenSearch, which SIEM needs).

### 0.2 Add to the private `.env` (main checkout root)
Pick your console account id now; this plan uses `mohith`. Tenant-scoped switches
key off that id.

```
CB_AI_ENABLED_TENANTS=mohith
CB_SIEM_ENABLED_TENANTS=mohith
CB_OPENSEARCH_URL=http://127.0.0.1:50920
CB_OPENSEARCH_NAMESPACE=configbridge-local
CB_OPERATOR_TOKEN=<32+ random characters>
CB_SMTP_ADDR=smtp.gmail.com:587
CB_SMTP_TLS_MODE=starttls
CB_SMTP_FROM=<you>@gmail.com
CB_SMTP_USERNAME=<you>@gmail.com
CB_SMTP_PASSWORD=<gmail app password>
CB_ALERT_EMAIL_ROUTES={"mohith":"<you>@gmail.com"}
```
Already present and required: `CB_AI_PROVIDER=gemini`, `CB_AI_MODEL`, `GEMINI_API_KEY`,
`CB_AI_DAILY_LIMIT`, `CB_AI_DAILY_TOKEN_LIMIT`, `CB_SIGNUP=open`, `CB_DEV_MASTER_KEY`
(lets the new account store secrets — `pkg/secrets/local.go`).

Generate the operator token: `[Convert]::ToBase64String((1..32|%{Get-Random -Max 256}))`

> Note: `.env` is plaintext. Gmail app password + Gemini key in it is fine for a
> hackathon; rotate both after the event.

### 0.3 Start services (from the repo root, PowerShell)
```powershell
# Postgres: your .env points at 127.0.0.1:5432; the installed service is stopped
Start-Service postgresql-x64-15            # admin shell; or: docker compose up -d postgres
# OpenSearch for SIEM
docker run -d --rm --name cb-opensearch -p 127.0.0.1:50920:9200 -e discovery.type=single-node -e DISABLE_INSTALL_DEMO_CONFIG=true -e DISABLE_SECURITY_PLUGIN=true -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m" opensearchproject/opensearch:3.9.0
# migrate + start API
.\scripts\load-env.ps1 -Bootstrap; go run ./cmd/bootstrap
.\scripts\load-env.ps1; go run ./cmd/api
```
Pass: API log has no `API startup failed`. A startup error names the bad setting
(`cmd/api/main.go`, `internal/app/*.go`).

### 0.4 Account, API key, secrets
1. Open `http://127.0.0.1:8080/ui/` → **Sign up**: account `mohith`, your name/email/password. You become `admin`.
2. **Users & keys** → your user → create an API key. Keep it for the PowerShell checks:
   ```powershell
   $H=@{Authorization='Bearer <your key>'}; $B='http://127.0.0.1:8080'
   ```
3. **Secrets** → add:
   | name | value | allowed host |
   |---|---|---|
   | `github_token` | your GitHub token | `api.github.com` |
   | `nvd` | your NVD key | `services.nvd.nist.gov` |
   | `github_bad` | `ghp_definitelynotvalid0000000000000000` | `api.github.com` |

   Pass: the list shows names, hosts and dates only — never values (`GET /secrets`).

### Adding a source (used by every step below)
UI **Add source** → **Paste a config** → paste the file → **Check config** → Connect
card → run the steps it offers (save → validate → preview → activate → test → run).
Edit the `id` only where the step says so.

---

## 1. Real data collection (the three live sources)

| # | Config | Auth / paging | Expected after **Run** |
|---|---|---|---|
| S1 | `configs/cisa_kev.json` | none / none | outcome `success`, pages 1, accepted ≈ 1766, quarantined 0 |
| S2 | `configs/github_members.json` | bearer / Link | outcome `success`, pages ≈ 4 (per_page 10), accepted ≈ 36 |
| S3 | `configs/nvd_kev_cves.json` | api_key header / offset | outcome `success`, pages ≈ 9 (200 per page), accepted ≈ 1765 |

Counts are today's real feed sizes and can drift. NVD sometimes answers 503:
then attempts > pages and the run may fail — that is real FR-7 behaviour; rerun later.

**Show the data:** **OCSF records** → pick the class/source → open a record (JSON viewer).
API: `irm "$B/records/vulnerability_finding?source=cisa_kev&limit=5" -Headers $H`,
`irm "$B/records/user_inventory?source=github_members&limit=5" -Headers $H`,
PRD view: `irm "$B/schema/users?source=github_members" -Headers $H`.

---

## 2. Functional requirements

| FR | Steps | Pass when |
|---|---|---|
| FR-1 Auth | S2 (Bearer) and S3 (`apiKey` header) succeed. Negative case: the first run of `github_alert_demo` in B-4 (wrong token). | Bad token: outcome `failed`, error `auth_failed`, **attempts 1** (credential errors are never retried — `retryDelay`). |
| FR-2 URL/method/params | Paste `configs/e2e/github_members_per_page_100.json` (same id `github_members`) → new revision → activate → Run. | Pages drop from ≈4 to 1, same ≈36 records. Only config changed, no code. |
| FR-3 Pagination | S2 (Link header) and S3 (offset `startIndex`). | Run detail shows multiple pages; it stops when the Link header has no `next` / a page comes back short (`engine.go` page loop). |
| FR-4 Schedule | Add `configs/e2e/cisa_kev_scheduled.json` (enabled, 60 s). Do not click Run. Watch **Runs** for 3 min. Then edit schedule `enabled:false`, save, activate. | A new run about every 60 s with no click (`runner.Schedule`, 1 s tick + `next_due`). After disabling, no new runs. |
| FR-5 Mapping | Open one KEV and one NVD record. | Rename: `cveID` → `finding_info.uid`. Nested: `cve.metrics.cvssMetricV31.0.cvssData.baseScore` → `vulnerabilities[0].cve.cvss[0].base_score`. Date: `dateAdded` "2026-10-30" → `time` epoch ms. Lookup: NVD `HIGH` → `severity_id` 4. |
| FR-6 Secrets | (a) `irm "$B/secrets" -Headers $H` (b) search the API console output for your token's first 8 chars (c) `psql` as admin: `SELECT body->'auth' FROM configs;` | (a) no values (b) not found (c) only the secret **name**. Values are AES-GCM ciphertext per tenant in `credentials_values`. |
| FR-7 Retries | Add `configs/e2e/nvd_timeout_demo.json` (1 s timeout, 2000-row page, 3 attempts) → Run. | outcome `failed`, error `timeout`, **attempts 3**, with about 1 s + 2 s backoff between them visible in API log lines `vendor request failed, retrying`. If NVD happens to answer within 1 s, rerun. |
| FR-8 429 | Not triggerable live — see the table at the top. Run `go test ./internal/engine -run "TestRateLimit" -v`. | Both tests PASS: waits the exact Retry-After seconds; gives up when it exceeds `max_retry_after_seconds`. |
| FR-9 Bad records | Add `configs/e2e/cisa_kev_strict.json` (CWE required) → Run. | outcome `completed_with_errors`, accepted ≈ 1591, quarantined ≈ 175 (KEV entries with empty `cwes`). **Quarantine** page: field `vulnerabilities.0.cwe.uid`, reason `required value is missing`. Valid records stored. |
| FR-10 Health | **Overview** page and `irm "$B/health" -Headers $H`; also open `$B/health` with `Accept: text/html`. | `cisa_kev` healthy; `cisa_kev_strict` degraded; `nvd_timeout_demo` timeout; bad-token source `auth_failed`. Last run and last clean success are shown separately; last success changes only on `success` (`store.Health`, `FinishRun`). |
| FR-11 Storage/upsert | Count, run S1 again, count again: `$n=0;$o=0;do{$p=@(irm "$B/records/vulnerability_finding?source=cisa_kev&limit=500&offset=$o" -Headers $H);$n+=$p.Count;$o+=500}while($p.Count -eq 500);$n` | Same total (≈1766) before and after the second run (`ON CONFLICT (tenant_id,source,external_id) DO UPDATE`). |

---

## 3. Bonus features

| Bonus | Steps | Pass when |
|---|---|---|
| B-1 Incremental | In `configs/e2e/github_committers_incremental.json` replace `your-owner/your-repo` with a repo you can push to (a scratch repo is fine) → add → Run (1). Push **one** commit to it → wait 2 s → Run (2) → Run (3). Check `irm "$B/connectors/github_committers_incremental/sync-state" -Headers $H`. | Run 1 accepts every commit since 2026-10-01. Run 2 accepts **1**. Run 3 accepts **0**. The watermark `through` advances only after clean runs (`FinishRun`: committed only on `success` with 0 quarantined). Preview/test never moves it. |
| B-2 Config validation | Paste a broken config, e.g. S1 with `"pagination":{"type":"pages"}`, or add `"tenant_id":"x"` → **Check config**. | Field-level errors (`pagination…`, `config: unknown key (including tenant_id)…`), HTTP 422, nothing saved, no network call (`POST /configs/check` → `config.Decode`). |
| B-3 Test connection | On S2 click **Test** (or preview a draft revision). | Result `mode: test`, ≤100 rows from the first page. **Runs** gets no new row, record count unchanged (`runner.run`: `test` skips `StartRun`/`SavePage`/`FinishRun`). |
| B-4 Email alerts | Add `configs/e2e/github_alert_demo.json` (wrong token, threshold 3). Run it 3× (wait ≥5 s between runs: limit is 6-run burst then 1 per 5 s). Check `irm "$B/alerts?connector=github_alert_demo" -Headers $H` and your inbox. Run a 4th time. **Do A-4 now**, before recovery. Then change the secret name to `github_token`, save, activate, Run. | After run 2: no alert. After run 3: one alert, status `sent`, email "ConfigBridge: repeated collection failures" with no secrets or records in it. Run 4: no second email (one per episode + cooldown). Recovery run: `success`, streak resets (`store/alerts.go`). |
| B-5 Source form | **Add source** → **Fill in manually**: build S1 again with a new id through the form (URL, items_path `vulnerabilities`, the same mappings as `configs/cisa_kev.json`; the validator refuses to save until every OCSF-required field is mapped) → save → validate → activate → test → run. | Same validator as the API; produces records; activation is a separate explicit step. |

---

## 4. AI features

| # | Steps | Pass when |
|---|---|---|
| A-1 Reviewed preset (not real AI) | Add source → AI mode → Product `CISA` → Set it up. | Draft card shows contract status `reviewed_profile` or `reviewed_profile_fallback`. Either way the config is the hardcoded `configs/cisa_kev.json` with the GitHub mirror URL. One metered call is still spent. |
| A-2 Real AI drafting | Product `GitHub` → dataset dropdown **Another dataset: use public API documentation** → dataset `repository contributors`, scope `repository`, URL `https://docs.github.com/en/rest/repos/repos#list-repository-contributors`, data `User inventory` → Set it up. Fill owner/repo → Apply → credentials (reuse `github_token`) → preview → activate → run. | Draft status `documented_candidate` with cited evidence per setting, then real contributor records. **Or** an honest 422 listing the missing evidence (Gemini is not deterministic). Either way, an invalid draft is never saved or run (`ai.generate`, `verifyDocumentation`). |
| A-3 Usage + audit | **AI usage** page; `irm "$B/ai/audit" -Headers $H`. | Each draft/explanation is listed with input/output/total tokens (or "unknown" with the 40 000 reservation held). Audit holds hashes only — no prompt or config text. |
| A-4 SIEM explain (live failures) | After FR-9 and B-4's 4 failed runs, **before** B-4 recovery (the rule counts consecutive failures from the latest run back — `store/siem.go`): **Insights** → source `github_alert_demo` → Refresh → topic *connection health* → Ask AI (consent). Repeat for `cisa_kev_strict`. | Findings `collection_failures` (category `auth_failed`, count ≥3) and `mapping_rejections` (count ≈175). Answer status `explanation_requires_review`, evidence ids `e1…`, allowed next-checks only, tokens added to AI usage. Only counts and categories are sent to the model (`insights.Evidence`). |
| A-5 SIEM security topic | Insights → `cisa_kev` → topic *security findings* → Ask AI. | Expected today: `no_findings`, no AI call, no tokens spent (see the top table). |
| A-6 Operator dashboard | Sign out → sign-in page link **Platform AI usage** (`/ui/#/platform-ai`) → paste `CB_OPERATOR_TOKEN`. | Per-account token totals, including `mohith`; read-only; reload asks for the token again. |
| A-7 Budget | Optional: set `CB_AI_DAILY_LIMIT=1`, restart, draft twice. | Second draft → HTTP 429 `ai_daily_limit_reached`. Restore the value afterwards. |
| A-8 Works without AI | Comment out `CB_AI_PROVIDER`, restart, re-run S1. | Collection, mapping and storage unaffected; AI draft answers `ai_not_configured`. |

---

## 5. Known defects found while reading the code

- `scripts/smoke-incremental.ps1` calls `/records/users`, which returns 404
  `unknown_ocsf_class` since the move to OCSF. It should use `/schema/users`.
  (Mock-based; not part of this plan.)
