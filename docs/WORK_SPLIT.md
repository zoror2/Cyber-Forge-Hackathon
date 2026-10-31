# ConfigBridge — Work Split

Config-driven security integration platform. Product, not a prototype: **security is the top priority.**

## Decisions

| Decision | Choice |
|---|---|
| Language | Go (rewrite of the current Python Milestone 1 code) |
| Cloud | AWS, we build and host |
| Tenancy | **Multi-tenant** (changed from single-tenant): one shared platform; isolation via RLS, tenant-scoped secrets/caches, per-tenant KMS keys. See MEMBER_B_HANDOFF §2.6 |
| Config format | JSON, stored in Postgres JSONB; entered through the UI form |
| Configs | Written by engineers only, entered through the hosted UI (phase 2) |
| Order | Phase 1: engine + API, tested in Postman. Phase 2: UI + AWS |
| Members | **Member A = Mohith** (request side). Member B = teammate (data side + API) |

Architecture diagram: [architecture.svg](architecture.svg)

---

## Phase 1 — Engine (both members)

### Day 1: shared contracts (together, before splitting)

1. **Config format**: Go structs + validation rules (auth, endpoint, pagination, schedule, mapping).
2. **DB schema**: `configs` (versioned, status `draft`/`approved`/`live`), `credentials_meta`, `users`, `devices`, `events`, `quarantine`, `runs`, `sync_state`. Every record has `source` and `fetched_at`.
3. **Secrets interface**: `GetSecret(name) -> (value, allowedHost)`.
4. **Run result format**: what the engine writes to `runs`.
5. **API endpoint list** (below), frozen.
6. **Hard rule:** the engine only runs configs whose status is `live` in the DB. Nothing else: no files, no request bodies.

### API (tested in Postman)

| Endpoint | Purpose |
|---|---|
| `POST /configs` | Submit a config (validated, stored) |
| `POST /configs/{id}/validate` | Return validation errors only (B-2) |
| `POST /configs/{id}/activate` | Mark it live (approval added in phase 2) |
| `PUT /secrets/{name}` | Body `{value, allowed_host}`; returns 204; **never echoes the value** |
| `GET /secrets` | Names, hosts, dates only; **never values** |
| `POST /connectors/{id}/test` | Test connection (B-3) |
| `POST /connectors/{id}/run` | Trigger a run now |
| `GET /runs?connector=` | Run history |
| `GET /health` | Per-connector status, last run, count, last error (JSON + simple HTML page) |
| `GET /records/{users\|devices\|events}` | Normalized data |
| `GET /quarantine?connector=` | Rejected records with reasons |

All endpoints require an admin token in phase 1. **Never unauthenticated, even in dev.** The token is replaced by SSO in phase 2; do not keep it as a backdoor.

### Member A: request side

| # | Task | Critical |
|---|---|---|
| A1 | **Egress guard**: secret only sent to its bound host; HTTPS only; no redirects; block localhost / private / link-local / `169.254.169.254` (checked after DNS resolution) | 🔴 no compromise |
| A2 | **Auth handlers**: API key, Basic, Bearer, OAuth2 client credentials (token in memory only). Secrets only via the auth block, never in `headers`/`params` | 🔴 |
| A3 | **Safe HTTP**: streamed body with size cap, max pages, max run time, timeouts | 🔴 |
| A4 | Retry with backoff 1s → 2s → 4s on timeouts and 5xx; HTTP 429 honours `Retry-After` | |
| A5 | Pagination: page number, Link header, cursor, offset | |
| A6 | **Log redaction**: never log tokens, auth headers, full URLs, or response bodies | 🔴 |
| A7 | **Mock vendor server** (Go): switchable 500 / 429 + `Retry-After` / hang / redirect / huge body / malformed record | |

### Member B: data side + API

| # | Task | Critical |
|---|---|---|
| B1 | Config schema + validation with clear errors | |
| B2 | Mapper → User / Device / Event (rename, nested paths, date → UTC); bad rows → quarantine with reason | |
| B3 | Postgres: migrations, upserts, `runs`, `sync_state` | |
| B4 | **Secrets backend**: local dev backend + AWS Secrets Manager behind the same interface; write-only via API | 🔴 |
| B5 | Scheduler with Postgres locks (no double runs) | |
| B6 | HTTP API above, admin-token protected; `/health` HTML page | 🔴 auth |
| B7 | Postman collection + environment | |
| B8 | `docker-compose.yml`: Postgres + engine + mock vendor | |

### Cross-review rule

- B reviews every PR touching **A1, A2, A3, A6**.
- A reviews every PR touching **B4, B6 auth**.
- No security-critical code merges with only its author's approval.

### Postman hygiene

Real vendor tokens live **only** in Postman Vault or local environment values. Never in synced/shared workspaces or exported collections.

---

## Phase 1 done criteria

**Must work**
- [ ] GitHub, Jira, NVD (and Okta) run live; records land in the right tables
- [ ] Re-run updates records, no duplicates
- [ ] Every record has `source` and `fetched_at`
- [ ] 1-minute schedule → 2 runs in `runs` within ~2 minutes
- [ ] Nested field + non-ISO date → stored renamed, flattened, UTC
- [ ] `/health` page shows status, last run, count, last error
- [ ] Someone who did not write the engine adds CISA KEV via config only, in under 1 hour

**Must fail safely**
- [ ] Wrong / expired key → run failed, no retry storm, redacted error
- [ ] Mock 500 ×3 → retries 1s, 2s, 4s → failed
- [ ] Mock hang past timeout → retries 1s, 2s, 4s → failed
- [ ] Mock 429 + `Retry-After: 5` → waits 5s → succeeds
- [ ] Malformed record → quarantined, rest of run succeeds
- [ ] Network cut mid-run → clean failure, no corruption
- [ ] Oversized response → cut at cap, clean failure

**Must refuse (security)**
- [ ] `jira_token` used against a non-Jira host → refused
- [ ] URL to `localhost`, `10.x`, `169.254.169.254` → refused
- [ ] Vendor redirect → not followed
- [ ] `http://` URL → refused
- [ ] Secret placed in `headers` / `params` → rejected at validation
- [ ] `GET /secrets` never returns a value
- [ ] Any request without admin token → 401
- [ ] Logs contain no tokens after all tests (grep them)
- [ ] gitleaks passes in CI / pre-commit

---

## FR coverage

| FR | Requirement | Owner | Test |
|---|---|---|---|
| FR-1 | Auth: API key + one more | A2 | GitHub (Bearer), Jira (Basic), NVD (API key) run live |
| FR-2 | URL, method, params | B1 | Configs with query params run |
| FR-3 | 2+ pagination styles | A5 | GitHub (Link) + Jira/NVD (offset) fetch all pages |
| FR-4 | Schedule | B5 | 1-min interval → 2 runs |
| FR-5 | Mapping | B2 | Nested + date conversion test |
| FR-6 | Secrets safe | B4, A1, A6 | No values via API, none in logs, gitleaks |
| FR-7 | Retry/backoff | A4, A7 | 5xx and timeout tests |
| FR-8 | 429 / Retry-After | A4, A7 | 429 test |
| FR-9 | Bad data | B2 | Quarantine test |
| FR-10 | Health view | B6 | `/health` page |
| FR-11 | One store, common schema | B3 | Users from GitHub + Okta in one `users` table; events from Jira + NVD |

**Open:** no chosen source produces **devices**. Find a free device API (verify Okta free plan) or document that `devices` is empty by design.

---

## Phase 2 — UI + AWS (after phase 1 passes)

**Member A: AWS + CI/CD**
- Terraform: dedicated AWS account per customer (Organizations), VPC with private subnets, ECS Fargate, RDS PostgreSQL (encrypted), Secrets Manager + KMS, ALB + WAF + ACM, egress allowlist
- IAM least privilege: app role can **read** secrets, never change host bindings
- GitHub Actions → AWS via OIDC (no stored AWS keys), `govulncheck`, Trivy, cosign image signing

**Member B: UI** (on top of the phase 1 API)
- SSO (OIDC) with MFA, HttpOnly session cookies, short sessions
- Roles: viewer, engineer, approver, secrets admin; enforced server-side
- Config workflow: draft → approved by a *different* person → live; versions + rollback
- Secrets screen: write-only; changing a host binding needs re-auth + second approver
- Append-only audit log; health page; CSRF + CSP; alerts on repeated failures (B-4)

## Non-negotiables (ranked)

1. **Egress guard with secret-to-host binding**: otherwise one compromised account leaks every vendor key.
2. **Write-only secrets, guarded binding changes**: otherwise the UI is a key-copying tool.
3. **Two-person config approval**: otherwise one stolen login is enough.
4. **SSO + MFA + server-side RBAC.**
5. **IAM least privilege + private networking**: otherwise an app bug becomes full AWS access.
