# Verification and PRD checklist

Audit date: 1 November 2026. Branch: `member-b`. Mohit's `main` at
`a03e3ed` was fast-forwarded locally, independently tested, then updated here.
A subsequent fetch found no newer `main` commit.

Additional commercial-vendor engine work and its explicit live-test blockers are
tracked in [VENDOR_TESTING.md](VENDOR_TESTING.md). Those local contract tests do
not certify the entire supplied vendor list.

Independent supplied-config scenarios and expected record values are documented
in [JURY_TESTS.md](JURY_TESTS.md).

The latest local AI workflow tests, parser fix, supported use cases and remaining
AI checklist are in [AI_LOCAL_TESTS.md](AI_LOCAL_TESTS.md). Those tests use model
stand-ins and do not replace the pending live-provider comparison.

This checklist uses **PRD_Security_Integration_Requirements_1.docx.pdf**.
Passing local tests is evidence for the supported contracts, not a promise that
every vendor, cloud deployment or future jury input will work.

## Functional requirements

| Requirement | Result | Evidence and limits |
|---|---|---|
| FR-1 Authentication | Implemented; local tests pass | API key, Bearer, Basic, OAuth2 client credentials and static multi-header credentials. Real GitHub Bearer and NVD header keys also tested. |
| FR-2 Configured endpoint | Implemented; local tests pass | HTTPS GET URL, query parameters, headers and timeout. Read-only JSON APIs; unsupported methods/protocols are rejected. |
| FR-3 Pagination | Implemented; local tests pass | Page, offset, cursor and Link; empty/short pages, cycles, malformed links and limits tested. GitHub Link and NVD offset exercised live. |
| FR-4 Scheduling | Implemented; local tests pass | Enabled/due jobs, tenant fairness, recovery and PostgreSQL connector locks. |
| FR-5 Common mapping | Implemented; local tests pass | Nested fields, conversions, timestamps and five OCSF 1.9 classes. PRD users/devices/events compatibility views exist. Missing source facts are not invented. |
| FR-6 Safe secrets | Implemented; local tests pass | Configs contain secret names. Local credentials use tenant-specific AES-GCM encryption; keys come from private environment configuration. AWS Secrets Manager/KMS adapter tested with mocks, **not a live AWS account**. |
| FR-7 Retry/backoff | Implemented; local tests pass | Bounded network/timeout/5xx retry. A real NVD 503 exhausted bounded retries, reported failure, and a later run succeeded. |
| FR-8 Rate limits | Implemented; local tests pass | HTTP 429 and bounded Retry-After handling within a run. No durable vendor-wide cooldown shared across runs. |
| FR-9 Bad records | Implemented; local tests pass | Invalid records quarantined; valid records continue. Failed/quarantined incremental runs do not advance the checkpoint. |
| FR-10 Health | Implemented; local tests pass | Connection outcome, last run, accepted/quarantined counts and errors; failed/interrupted outcomes remain visible. |
| FR-11 Central storage | Implemented; local tests pass | OCSF PostgreSQL records, tenant RLS and upsert; repeating each of the three live sources did not add duplicates. |

FR-6 allows encryption **or** environment/vault storage. It does not require a
live AWS vault to satisfy the local encrypted-storage option. A private `.env`
is plaintext on disk: protect it and never commit it. Application IAM and AWS IAM
are different things.

## Bonuses

| Bonus | Result | Evidence and limits |
|---|---|---|
| B-1 Incremental sync | Implemented; local contract tests pass | Supported time-window checkpoints, restart, pagination, tenant separation and failed-run safety. Not automatically enabled for arbitrary vendors; no live incremental-vendor proof in this audit. |
| B-2 Config validation | Implemented; local tests pass | Clear pre-network schema/security errors and non-saving config check. |
| B-3 Test connection | Implemented; local tests pass | Preview does not persist collected records, run history or checkpoints. |
| B-4 Repeated-failure alerts | Implemented; local SMTP tests pass | Email threshold, outbox, retry cap, cooldown, recovery and isolation. Delivery through a real external email service remains unverified. |
| B-5 Source form | Implemented; browser flow passes | Explicit dataset, local credential/path inputs, validation, preview, activation and first fetch. AI is optional; see hosted-provider caveat below. |

## What was exercised

- Independent merged-main baseline: format, vet, race tests and builds passed.
- Regression gate with real **Docker PostgreSQL and OpenSearch** passed, including
  IAM, tenant isolation, SIEM, token accounting, incremental sync and email capture.
  Go tests run on Windows against Docker services. Separately, the existing full
  Docker application image was built and exercised: API, bootstrap, TLS mock
  vendor, PostgreSQL, collection/upserts/quarantine and the usage console passed.
  The image runs non-root with a read-only filesystem and dropped capabilities.
- Release-source scan: Gitleaks found no secrets; an exact-value check also
  found none of the private environment credentials in candidate source files.
  `.env`, downloaded tools and local evidence remain ignored by Git.
- Headless Edge: signup/session, reviewed source selection, local input checks,
  clear missing-docs error, manual config check, preview, activation, fetch and
  displayed stored record; no JavaScript errors.
- Real sources through API, engine, mapper and PostgreSQL, **with AI unavailable**:
  GitHub contributors: 3 records; NVD KEV subset: 1,765 records over 9 pages;
  CISA KEV official mirror: 1,766 records. Each was run twice; counts stayed stable.
  These counts describe that test snapshot, not permanent feed sizes.
- NVD initially returned repeated 503s; its later successful repeat used the same
  production config. An upstream outage cannot be eliminated by local tests.
- Local no-AI test: AI endpoint unavailable, manual config still validates,
  previews, activates, collects and upserts; another tenant sees no records.
- Migration regression: old Member B SIEM migration numbering, historical
  users/devices/events, SIEM snapshots and token accounting survive the upgrade.
  Running migration twice and upgrading an already-OCSF database also pass.

## AI evidence and limitations

The generalized drafter requires the requested dataset, access scope and public
API reference links. It retrieves those references itself and checks literal
evidence for the endpoint, authentication, pagination, collection and mapped
fields. Unknown vendors do not require a new hardcoded collector. Unsupported or
undocumented contracts fail clearly. See [AI_DRAFTS.md](AI_DRAFTS.md).

GitHub, NVD and CISA also have reviewed reference profiles. Live Groq calls for
these profiles returned the explicit `reviewed_profile_fallback` status: the
reviewed config was retained when the model proposal differed. This is not proof
that the model independently reconstructed those contracts.

The supplied Gemini key successfully accessed the API. Gemini 3.5 Flash passed
a live generic GitHub documentation check with 12 citations. A repeat call was
rejected as an invalid draft; Gemini also returned busy responses during testing.
Gemini 3.8 calls timed out. **Hosted drafting is not guaranteed to succeed on every
call.** Invalid drafts are not saved or executed. The private runtime provider
remains unchanged until repeat verification is satisfactory.

The generic generated-config-to-real-GitHub test has not completed successfully
in the latest provider comparison. Hosted drafting still needs live verification.
The complete local gate passed (`ai-dashboard-final-gate.log`, integration
package 120.605 seconds), including the new AI consumption report tests.
See [AI_USAGE.md](AI_USAGE.md) for dashboard security, Docker browser checks and
the distinction between reported tokens and unknown reservations.

Customer records, credential values, stored-secret metadata and local path
inputs are not sent to the config drafter. Product/dataset/scope and supplied
public reference text are sent: do not put private material into those fields or
links. Citation presence does not prove publisher authenticity or correct
business meaning; choose trusted documentation and preview before activation.

## IAM and remaining limits

- App IAM verified: accounts, viewer/operator/editor/admin permissions, tenant
  ownership, key limits/revocation, JWT tamper rejection, refresh rotation, logout,
  HttpOnly cookies and CSRF protections.
- Live AWS IAM policy, Secrets Manager/KMS access and Bedrock remain unverified.
  SSO, MFA and two-person approval are not claimed.
- Worker capacity is bounded per process; it is not a cluster-wide job quota.
  Same-connector PostgreSQL advisory locks do work across processes.
- Run summaries persist at finalization; page-by-page progress is not durably
  checkpointed. A process crash can lose intermediate counters.
- OAuth client-credentials tokens can be reacquired. This is not a generic
  refresh-token flow and cannot renew static personal-access tokens.
- Old pre-OCSF records are preserved in operator-only `legacy_*` tables, not
  silently deleted. They require reviewed conversion or replay to appear in the
  new OCSF views. Existing configs also need OCSF-compatible mappings.
- The three-real-source requirement has now been demonstrated with GitHub, NVD
  and CISA; the earlier reminder about a missing third API is obsolete.

## Reproduce

Use a disposable Docker PostgreSQL admin URL in `TEST_DATABASE_URL` and a local
test OpenSearch URL in `TEST_OPENSEARCH_URL`, then run `scripts/check.ps1`.
It checks formatting, vet, all ordinary tests with the race detector and builds
all six commands. Tests create isolated database schemas/roles and clean them up.

Live tests are separate, opt-in and make paid/rate-limited external requests:

```powershell
# Load private credentials locally; never paste keys into commands or commits.
. ./scripts/load-env.ps1 -Bootstrap
$env:CB_LIVE_AI_PROVIDER = 'gemini'
$env:CB_LIVE_AI_MODEL = 'gemini-3.5-flash'
$env:CB_LIVE_DOCUMENTATION = '1'
go test -v -count=1 -timeout=4m ./internal/ai -run '^TestGenericLiveGithubDocumentation$'
```

Local evidence is in ignored `data/`: `main-independent-baseline.log`,
`merged-full-gate.log`, `final-regression-gate-v2.log`,
`reviewed-authenticated-proof.log`, `real-three-source-api-proof.log`,
`real-nvd-api-proof.log`, `browser-audit-proof.log`,
`gemini-35-generic-live-proof.log` and `gemini-generated-config-final-proof.log`.
These logs are not committed with private workspace data.

## Explain the changed files simply

| File | What it does |
|---|---|
| `internal/ai/documentation.go` | Downloads public docs and checks that the proposed settings have evidence. |
| `internal/ai/reviewed.go` | Keeps reviewed examples for the three demo sources and asks for the correct dataset. |
| `internal/ai/ai.go` | Coordinates drafting, validation, bounded repairs and token usage. |
| `internal/ai/gemini.go` | Talks to Gemini with private header authentication and bounded responses. |
| `internal/api/api.go` | Checks the request and public docs before reserving paid AI tokens. |
| `internal/ui/static/app.js` | Shows scope, source links, credential fields and separate owner/repo inputs. |
| `internal/ui/ui.go` | Serves the UI; its cookie documentation now matches IAM. |
| `configs/embed.go` | Makes the CISA example available to the Go drafter. |
| `internal/store/store.go`, `migrations/006_ocsf.sql` | Upgrade the database without deleting old records or confusing migration numbers. |
| `internal/store/exposure.go` | Recognizes CISA's exact official mirror as a trusted KEV source. |
| AI `*_test.go` files | Test wrong scope, fabricated facts, privacy, provider errors and optional live calls. |
| `internal/store/upgrade_test.go` | Checks that upgrading preserves old data and keeps archives private. |
| `tests/engine_without_ai_test.go`, `tests/live_sources_test.go` | Prove collection and storage work without an LLM. |
| `tests/ai_metering_test.go`, `tests/exposure_test.go` | Verify billing isolation and KEV source provenance. |
| This file and `AI_DRAFTS.md` | Explain what was tested, what is limited and how the source form works. |
