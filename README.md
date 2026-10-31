# ConfigBridge

ConfigBridge is a Go platform that collects JSON APIs using declarative configs,
converts every record into an **OCSF 1.9.0** event (the open security schema used by
AWS Security Lake, Splunk and others), and stores them in PostgreSQL. The current implementation combines Mohith's request engine with
Prajwal's data layer and API. The team now uses **multi-tenancy**, as documented
in [WORK_SPLIT.md](docs/WORK_SPLIT.md) and [MEMBER_B_HANDOFF.md](docs/MEMBER_B_HANDOFF.md).

```text
tenant API key → live DB config → guarded HTTP/auth/retry/paging engine
              → filter → OCSF mapper (pinned schema) → PostgreSQL ocsf_records + quarantine → runs/health API
```

The working local sources are synthetic TLS fixtures. Live vendor credentials,
real AWS Secrets Manager access, cloud deployment, SSO and two-person config
approval remain separate work. The engine supports the specific auth/paging
capabilities in its config contract; it does not support every vendor protocol.

## Local setup (Windows PowerShell)

Prerequisites: Go 1.27+, PostgreSQL 16+, and a C compiler for race-detector tests.
Docker Compose is an alternative local runtime. Runtime data, certificates,
downloaded tools and `.env` are ignored by Git.

If using the portable toolchain already downloaded in this workspace, add it to
the current terminal's PATH first:

```powershell
$env:PATH = "$PWD\.tools\go\bin;" + $env:PATH
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts/dev-env.ps1
```

This generates distinct database credentials, a tenant API key, a development
tenant encryption keyring, and the local mock TLS certificate without printing
credential values. It refuses to overwrite `.env`. Preserve existing tenant keys;
changing them loses access to encrypted development secrets. `.env` is plaintext
protected by local filesystem permissions.

For native PostgreSQL, create a disposable database and edit the two database
URLs in `.env`: `MIGRATION_DATABASE_URL` uses a trusted migration/provisioning
account; `DATABASE_URL` uses the restricted `configbridge_app` account. The
development bootstrap can create the latter role. It cannot be the migration
owner, a superuser, or an RLS-bypassing role.

Terminal 1 (provision, then start API):

```powershell
.\scripts\load-env.ps1 -Bootstrap
go run ./cmd/bootstrap
.\scripts\load-env.ps1
go run ./cmd/api
```

Terminal 2 (TLS synthetic vendor):

```powershell
.\scripts\load-env.ps1
go run ./cmd/mockvendor
```

Terminal 3:

```powershell
$env:CB_SMOKE_VENDOR_URL = 'https://127.0.0.1:8081'
.\scripts\smoke.ps1
```

Expected: three pages and 25 accepted users per run, 25 unique users after two
runs, then two accepted/two quarantined from the malformed response. Connection
tests write no production records, quarantine, run history or sync state.

### Compose alternative

```powershell
docker compose up --build -d api
.\scripts\smoke.ps1
```

Compose adds PostgreSQL, a separate bootstrap job, API, and the TLS mock. API and
mock run without root, with a read-only filesystem, capabilities dropped, and
loopback-only published ports. The mock key is a development-only bind mount;
Linux users must grant the nonroot container UID read access to that key.
Docker startup itself has not been verified on the current Windows machine.

## Test before pushing

After fetching/merging teammate changes, first check their baseline. Work through
each changed feature locally, then run the full gate with real PostgreSQL:

```powershell
# Use a disposable admin DB: tests create isolated schemas and non-owner roles.
$env:TEST_DATABASE_URL = $env:MIGRATION_DATABASE_URL
.\scripts\check.ps1
```

The gate checks formatting, `go vet`, every Go test with `-race`, and native builds
for API/bootstrap/mock/certificate generation. It requires the database URL so
integration tests cannot silently skip. A failed check prevents pushing. The
same suite is available as `docker compose --profile tools run --rm test`;
dependencies download separately, then the test network has no internet egress.
The native gate is the verified option on this machine.

Full HTTP/PostgreSQL tests cover both tenants, page mapping/upserts, invalid rows,
dates, all auth types, secret host binding/rotation, failures/recovery, queue and
lock behavior, scheduling, and API authorization. See the measured matrix in
[docs/MEMBER_B.md](docs/MEMBER_B.md). Fixture tests do not establish live-vendor
access or a production capacity claim.

## API and configuration

Import [postman/ConfigBridge.collection.json](postman/ConfigBridge.collection.json)
and its environment. Fill `api_key` locally from your generated value; keep
credentials out of synced/shared environments and exports. Vendor tokens belong
in Postman Vault. The isolation folder requires a separately provisioned tenant B
and its own local API-key value.

Every endpoint requires `Authorization: Bearer <tenant API key>`. PostgreSQL stores
only its SHA-256 hash. Tenant identity comes from authentication; no body, URL or
caller-selected tenant header can choose it. Unknown/other-tenant connector IDs
return 404. Collection routes return only the authenticated tenant's data.

| Route | Purpose |
|---|---|
| `POST /configs` | Strict JSON → new draft revision, no network call |
| `POST /configs/{id}/validate` | Validate the stored config |
| `POST /configs/{id}/activate` | Body `{"revision":1}`; select the live version |
| `PUT /secrets/{name}` | Body `{value,allowed_host}`; 204 and no value returned |
| `GET /secrets` | Names, host bindings and dates only |
| `POST /connectors/{id}/test` | Empty body; one-page/100-row sample, no writes |
| `POST /connectors/{id}/run` | Empty body; synchronously run the live DB config |
| `GET /runs?connector=` | Paginated history |
| `GET /health` | JSON health, or escaped HTML with `Accept: text/html` |
| `GET /records/{ocsf_class}?source=` | Paginated OCSF records: `vulnerability_finding`, `detection_finding`, `user_inventory`, `inventory_info`, `authentication` |
| `GET /quarantine?connector=` | Paginated rejection metadata |

List defaults: `limit=100&offset=0`; maximum limit 500. Busy connectors/capacity
return 409. Failed vendor collections return 502 with a sanitized persisted run
result. Runs with invalid rows complete with errors and show degraded health.
Only a clean success changes `last_success`; partial runs never advance a
watermark. The watermark column is reserved and unused.

See [configs/mock_users.json](configs/mock_users.json) for the full config. The
request half uses Member A's exact field names: `auth.secret`, `items_path`,
pagination `none/page/offset/link/cursor`, and retry `base_delay_ms`. Date layouts
use Go notation (`2006-01-02`), with an explicit IANA timezone for naive dates.
User-supplied `tenant_id`, unknown keys and duplicate JSON keys are rejected.

## Security boundaries

- All customer tables include tenant keys and forced PostgreSQL RLS. Each data
  transaction sets a transaction-local tenant; it cannot leak into pooled
  connections. The runtime role cannot own tables, bypass RLS or be superuser.
  Narrow security-definer functions only authenticate key hashes and enumerate
  due/abandoned job IDs. They use schema-qualified tables and fixed search paths.
- Development secrets use separate AES-256-GCM keys per tenant and authenticated
  tenant/name binding. The AWS backend uses tenant-prefixed names and each
  tenant's KMS key. Host/backend bindings are immutable through the API. Live AWS
  is unverified, and phase 2 must separate secret provisioning from read-only IAM.
- All outbound requests use Member A's egress client: HTTPS, certificate checking,
  no redirects/proxy environment variables, destination checks after DNS, and
  exact secret-to-host binding. Native/Compose mocks use TLS with an explicitly
  trusted development CA; production refuses every development override.
- Retry/page/size/time limits apply before storage. Log and run errors omit
  credential values and vendor bodies. Quarantine stores only tenant, run, page,
  index, field and a fixed reason, deliberately avoiding raw PII/credential dumps.
- Per-tenant capacity prevents one tenant taking both workers; PostgreSQL locks
  include tenant + connector and cover manual/scheduled runs. Lost lock sessions
  cancel work, and run-state checks fence abandoned writers. This requires direct
  or session-pooled PostgreSQL connections, not transaction-mode PgBouncer.
- Phase 1 API keys and activation are not the phase 2 SSO/RBAC/approval workflow.
  Remote production hosting and customer onboarding remain outside this release.

Cross-review remains required for security-sensitive code. Push only a branch;
Member A reviews our secrets/API auth before merge. Request-engine details and
the broader target-integration analysis remain in [REQUEST_SIDE.md](docs/REQUEST_SIDE.md)
and [MEMBER_B_HANDOFF.md](docs/MEMBER_B_HANDOFF.md).

## Web console

`http://127.0.0.1:8080/ui/` (served by the same binary, `internal/ui`). Sign in with the tenant API key; it stays in
the tab's memory only (no localStorage/cookies, gone on reload). Views: overview/health, connectors, **form config
builder (B-5)** with OCSF path suggestions and the save → validate → activate → test → run pipeline, OCSF records with a
JSON viewer, quarantine grouped by cause, runs, secrets (write-only). Strict CSP (`'self'` only, no inline script, no
CDNs); every vendor value is rendered as text. Same-origin browser calls are allowed; cross-site requests get 403.

## Live sources (PRD: three real free-tier sources)

| # | Source | Config | Auth | Paging | Status |
|---|---|---|---|---|---|
| 1 | CISA KEV → OCSF Vulnerability Finding (2002) | [configs/cisa_kev.json](configs/cisa_kev.json) | none | none | ✅ live: 1766 received / 1766 accepted / 0 quarantined; re-run upserts (no duplicates); filter demo: ransomware-linked only = 361 accepted / 1405 skipped |
| 2 | GitHub REST (OWASP public members) → OCSF User Inventory Info (5003) | [configs/github_members.json](configs/github_members.json) | bearer | Link header | ✅ live: 4 pages, 36 / 36 / 0; re-run upserts; token never in logs or DB |
| 3 | NVD CVE API (KEV subset, with CVSS) → OCSF Vulnerability Finding (2002) | [configs/nvd_kev_cves.json](configs/nvd_kev_cves.json) | api_key | offset | ✅ live: 9 pages, 1765 / 1765 / 0; re-run upserts; key never in logs or DB |

Evidence (config hash, UTC time, counts, outcome) is in [docs/LIVE_EVIDENCE.md](docs/LIVE_EVIDENCE.md).
How to write a config, with every field explained: [configs/README.md](configs/README.md).

## FR traceability

| FR | Implementation and evidence | Remaining |
|---|---|---|
| 1 Auth | A's `internal/engine/auth.go`, tenant-scoped secrets, unit + integrated auth tests; credential failures classified, never retried; `/validate` warns on a missing or wrongly bound secret | ✅ live: bearer (GitHub), api_key (NVD); basic/oauth2 tested against the mock |
| 2 URL/method/params | Shared A contract + strict `pkg/config`; invalid-config tests | Additional protocols deferred |
| 3 Paging | A engine; page/offset/link/cursor tests and real local page-to-DB runs | ✅ live: Link (GitHub, 4 pages), offset (NVD, 9 pages) |
| 4 Schedule | `internal/runner`, PG locks and two-tenant scheduling tests | 60-second live-provider demo |
| 5 Mapping | `pkg/mapping` → `pkg/ocsf`: every mapping key checked against the pinned OCSF 1.9.0 schema at validate time; nested/index/default/date/enum/trim/exact-number tests; client-side `filter` block | None for tested capabilities |
| 6 Secrets | RLS + per-tenant encrypted/AWS backends, binding/redaction/isolation tests | Live KMS/IAM review |
| 7 Retries | A retry engine + integrated failure/exhaustion/timeout tests | Live provider behavior |
| 8 429 | Seconds/date/delay-cap unit tests and actual 1-second local wait | Persistent next-retry eligibility extension |
| 9 Bad rows | OCSF type/enum/required validation + page/index quarantine with the OCSF field path; integrated malformed fixture | Raw payload intentionally omitted |
| 10 Health | Protected JSON/escaped HTML, history and failure tests; web console overview (`internal/ui`) | SSO |
| 11 Common storage | Common schema = **OCSF 1.9.0**, one `ocsf_records` table (class_uid + jsonb), tenant/source/ID upserts, actual PG RLS tests; **live: 1766 KEV findings + 36 GitHub users, re-runs unchanged** | Sources 2 and 3 live |

The Python files are removed from this branch. GitHub's PR diff still lists their
**deletions** because the base branch previously contained them. For a short file
explanation, see [CODE_WALKTHROUGH.md](CODE_WALKTHROUGH.md).

## Request engine: Member A additions on this branch

Added on top of the merged engine (all covered by tests in `internal/egress` and `internal/engine`):

- **Egress hardening:** refuses legacy numeric hosts (`127.1`, `0x7f000001`, `2130706433`), IPv6 zone IDs and non-ASCII hostnames; per-connector `request.allowed_ports` (default `[443]`, applied to API and token URLs); secrets bind to a **list** of exact hosts, wildcards refused; `Policy.ProductionSafe()`; every block logged as `event=egress_blocked`. Fuzz tests for host binding and IP checks.
- **Multi-field secrets:** `engine.NewSecretFields(map, hosts...)` for `client_id` + `client_secret`, `key_id` + `key`, etc. `engine.NewSecret(value, host)` still works unchanged.
- **`static` auth:** headers built from secret fields with `{{secret.<field>}}` placeholders only (e.g. Okta `Authorization: SSWS {{secret.value}}`, Cortex two-header keys). CR/LF in a secret is refused.
- **OAuth2:** `client_id` / `client_secret` from config or secret fields; non-secret `extra_params` (e.g. Wiz `audience`).
- **Credential errors:** `*engine.AuthError` with `Status` (`missing`, `incomplete`, `binding_mismatch`, `needs_reauth`, `insufficient_permissions`) and `CredentialID` (`Secret.WithID`), logged as `event=auth_failed`. 5xx/429 are never credential errors. Credential errors are **never retried** (a missing secret fails in 1 attempt, not 4), and runs/health report them as `credential_missing`, `credential_incomplete`, `credential_binding_mismatch` or `auth_failed` instead of `collection_failed`.
- **`cmd/fetch`:** dev command that runs one engine connector JSON from `examples/` against the TLS mock, using the same `internal/app.Policy` dev rules as the API: `docker compose --profile tools run --rm fetch -config /examples/mock_users.json`.

### Docs

| Doc | Content |
|---|---|
| [configs/README.md](configs/README.md) | **Config template**: every field, filter, OCSF classes and mapping paths, auth examples, storing a secret, what is refused |
| [docs/CONFIG_SHAPE.md](docs/CONFIG_SHAPE.md) | (roadmap) Two-layer config (reviewed vendor templates + tenant connectors), credential records, research on the 35 roadmap vendors |
| [docs/AI.md](docs/AI.md) | (roadmap) AI gateway, AI for configs, prompt-injection and poisoning defences, evals |
| [docs/AUTOMATION.md](docs/AUTOMATION.md) | (roadmap) What gets automated for users, and what never is |
| [docs/LIVE_EVIDENCE.md](docs/LIVE_EVIDENCE.md) | Redacted live-run evidence for the three real sources (PRD §15) |
| [docs/SYSTEM_DESIGN.md](docs/SYSTEM_DESIGN.md) | Built architecture, run lifecycle, ranked optimization points (O1–O8) with code references |

**Scope:** PRD first (FR-1..FR-11, three live free-tier sources). Decided 2026-10-31: the common schema is **OCSF 1.9.0** instead of a home-grown User/Device/Event model. The PRD lets us define the common schema; OCSF covers its user/device/event shapes (User Inventory, Device Inventory, Findings) and is what SIEMs and Security Lake ingest without conversion. Roadmap after the PRD: 35 enterprise vendors, SIEM destinations, AI config drafter, KEV-to-connected-vendor/credential exposure matching.
