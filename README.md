# ConfigBridge

**A config-driven security integration platform.** It pulls data from security tools (EDR, firewalls, SIEMs, DLP, cloud security) into one database in one common format, so a security team can answer "who has access", "what's exposed" and "what's open" in one place instead of 20 consoles.

Adding a new tool means writing a **connector config**, not new code. The engine handles authentication, pagination, retries, rate limits, secret safety and health for every connector the same way.

> **Status:** early development. Request-side engine (Member A) is scaffolded and tested. Data side + API (Member B) not started. Not production-ready.
> **Product, not a prototype:** security is the top priority. Single-tenant (one isolated AWS deployment per customer).

---

## Contents

1. [How it works](#how-it-works)
2. [Current status](#current-status)
3. [Quick start](#quick-start)
4. [Repository layout](#repository-layout)
5. [What each part does](#what-each-part-does)
6. [Security model](#security-model)
7. [Mock vendor](#mock-vendor)
8. [Development rules](#development-rules)
9. [Target integrations](#target-integrations)
10. [Documents](#documents)

---

## How it works

```
 config (approved, live) ─┐
                          ▼
 secret store ──► AUTH: attach credential (only if request host = secret's bound host)
                          ▼
                 EGRESS GUARD: HTTPS only · public IPs only (checked after DNS) · no redirects
                          ▼
                 SAFE HTTP: timeouts · response size cap
                          ▼
     5xx / timeout ──► retry after 1s, 2s, 4s, then fail
     429           ──► wait Retry-After, then retry
     401/403/404   ──► fail immediately (no retry storm)
                          ▼
                 PAGINATION: page / offset / Link header / cursor · page + time limits
                          ▼
                 records ──► MAPPER (Member B) ──► Postgres: users / devices / events
                                                   bad rows ──► quarantine
                          ▼
                 run result ──► runs table ──► health page / API
```

Everything logged is redacted: no tokens, no auth headers, no query strings, no response bodies.

---

## Current status

| Area | Owner | State |
|---|---|---|
| Egress guard (SSRF + secret-to-host binding) | A | ✅ scaffold + tests |
| Auth: API key, Bearer, Basic, OAuth2 client credentials | A | ✅ scaffold + tests |
| Retry/backoff, 429 Retry-After | A | ✅ scaffold + tests |
| Pagination: page, offset, Link header, cursor | A | ✅ scaffold + tests |
| Size / page / run-time limits, log redaction | A | ✅ scaffold + tests |
| Mock vendor for failure testing | A | ✅ |
| Full config schema + mapping to common schema | B | ⬜ not started |
| Postgres storage, quarantine, runs | B | ⬜ not started |
| Secrets backend (dev + AWS Secrets Manager) | B | ⬜ not started |
| Scheduler | B | ⬜ not started |
| HTTP API + health page (Postman testing) | B | ⬜ not started |
| UI, SSO, approvals, AWS deployment | A + B | ⬜ phase 2 |

"Scaffold" = works and is tested, not yet hardened. We go feature by feature next (see [WORK_SPLIT.md](docs/WORK_SPLIT.md)).

**Legacy:** `configbridge/`, `tests/`, `configs/` and `pyproject.toml` are the earlier Python Milestone 1 prototype. They are superseded by the Go engine and will be removed once Member B's data side replaces them. Do not extend them.

---

## Quick start

Everything builds and runs **in Docker**. You do not need Go installed (install it only if you want editor autocomplete).

### Prerequisites

- Docker Desktop running (`docker version` shows a Server section)
- Git

### Run all checks (formatting, vet, tests)

```bash
docker compose --profile tools run --rm test
```

Runs `gofmt` check, `go vet` and all tests with the race detector, **with no network access** (tests never touch real APIs). Expected output:

```
ok   configbridge/internal/egress
ok   configbridge/internal/engine
```

Non-zero exit = something failed. Unformatted files are listed by name.

### See each test by name

```bash
docker compose --profile tools run --rm test go test -count=1 -v ./internal/...
```

### Fix formatting

```bash
docker compose --profile tools run --rm test gofmt -w .
```

### Start the mock vendor

```bash
docker compose up -d --build mockvendor     # http://127.0.0.1:8081
curl -i "http://127.0.0.1:8081/ratelimit?key=a&retry_after=5"   # → 429 + Retry-After: 5
docker compose down                         # stop
```

It binds to `127.0.0.1` only, so it's never exposed on your network.

---

## Repository layout

```
go.mod                          Go module "configbridge" (no third-party dependencies)
internal/
  egress/
    egress.go                   WHERE requests may go (the security gate)
    egress_test.go
  engine/
    spec.go                     connector config (request part) + validation
    secret.go                   unprintable Secret type + SecretStore contract
    auth.go                     attaching credentials (API key, Bearer, Basic, OAuth2)
    engine.go                   Fetch loop: retries, 429, pagination, limits
    redact.go                   strip URLs before logs/errors
    engine_test.go
cmd/
  mockvendor/main.go            fake vendor API for failure testing (never deploy)
Dockerfile                      builds any cmd/<name> into a distroless non-root image
docker-compose.yml              test runner + mock vendor (Member B adds Postgres + API)
.dockerignore                   keeps .git, .env, docs, legacy code out of builds
.gitattributes                  forces LF line endings (gofmt in Linux Docker)
docs/
  WORK_SPLIT.md                 who builds what, done criteria, FR coverage
  REQUEST_SIDE.md               function-by-function guide to Member A's code
  MEMBER_B_HANDOFF.md           contracts and instructions for Member B
  architecture.svg              target architecture diagram
PRD.md                          detailed product requirements
configbridge/ tests/ configs/   LEGACY Python prototype (to be removed)
```

---

## What each part does

Full function-by-function detail: [docs/REQUEST_SIDE.md](docs/REQUEST_SIDE.md).

### `internal/egress`: the security gate

Every outbound request goes through it.

- **HTTPS only.** No `http://`, no `user:pass@host` in URLs.
- **Secret-to-host binding.** Each secret is stored with the one host it may go to. `jira_token` can only reach `yourcompany.atlassian.net`; a config pointing it anywhere else is refused before anything is sent.
- **Public IPs only, checked at connect time.** Blocks localhost, private networks (10/172.16/192.168), cloud metadata (`169.254.169.254`), carrier NAT, multicast and IPv6 equivalents. The check runs on the resolved IP, so a hostname secretly pointing at an internal address is still refused.
- **No redirects, no proxy env vars,** TLS 1.2+.
- Dev/test overrides (`AllowPrivate`, `AllowHTTP`, `RootCAs`) exist for the mock vendor and tests only; production must use the zero `Policy{}`.

### `internal/engine`: fetching data

- **`spec.go`**: the request half of a connector (URL, params, headers, auth type + secret *name*, pagination, limits, retry) with safe defaults. `Validate()` returns every problem at once and rejects secrets placed in headers or query params.
- **`secret.go`**: `Secret` can't be printed by any path (fmt, JSON, slog, even nested in hidden struct fields). `SecretStore` is the interface Member B's backend implements.
- **`auth.go`**: attaches credentials after checking the bound host. OAuth2 tokens live in memory only and refresh before expiry.
- **`engine.go`**: `Fetch()` walks every page, retries correctly, honours rate limits, enforces size, page and time limits, refuses next-page links that point to another host, and hands each page of raw records to a callback (Member B's mapper).
- **`redact.go`**: URLs in logs and errors keep only `scheme://host/path`.

### `cmd/mockvendor`: failure testing

A fake vendor that misbehaves on demand. See [Mock vendor](#mock-vendor).

### Docker

- **`Dockerfile`:** two-stage build into `distroless/static:nonroot`, with no shell and no package manager (about 3.5 MB image). Base images must be pinned by digest before production.
- **`docker-compose.yml`:** `test` service (offline checks) and `mockvendor` (read-only filesystem, all capabilities dropped, loopback-only port).

---

## Security model

Non-negotiable controls, in priority order:

1. **Secret-to-host binding** (egress guard). Even a fully compromised UI account can't send a key to an attacker's server.
2. **Write-only secrets.** Once saved, never shown again, via UI or API.
3. **Two-person config approval** (draft → approve by someone else → live). The engine only runs `live` configs from the database.
4. **SSO + MFA + server-side role checks** on every API call (phase 2).
5. **Least-privilege AWS IAM + private networking**, one AWS account per customer.

Plus: read-only vendor tokens, redacted logs, response size caps, no redirects, append-only audit log, stdlib-only Go (minimal supply chain), distroless non-root containers.

Found a way around any of these? Treat it as a bug with top priority.

---

## Mock vendor

`http://127.0.0.1:8081` after `docker compose up -d mockvendor`. **Test tool only.**

| Endpoint | Simulates |
|---|---|
| `GET /users?page=1&per_page=10` | 25 users, page numbers + `Link` header (GitHub-style) |
| `GET /issues?startAt=0&maxResults=10` | 25 issues, offset paging (Jira-style), records under `issues` |
| `GET /events?after=` | Cursor paging, records under `data`, cursor at `meta.next` |
| `GET /secure` | 401 unless `Authorization: Bearer mock-token` (wrong key test) |
| `GET /flaky?key=k1&fail=3&code=500` | Fails 3 times for key `k1`, then succeeds (retry test) |
| `GET /ratelimit?key=k1&retry_after=5` | One 429 with `Retry-After: 5`, then succeeds |
| `GET /hang?seconds=60` | Never answers in time (timeout test) |
| `GET /redirect` | 302 to the cloud metadata IP (redirect must be refused) |
| `GET /huge?mb=50` | 50 MB body (size cap test) |
| `GET /malformed` | Records with missing IDs, bad dates, nulls (quarantine test) |
| `GET /offhost` | Next-page link pointing at another host (must be refused) |
| `POST /reset` | Reset flaky/ratelimit counters |

---

## Development rules

- **Branch per feature**, PR into `main`. Never push to `main` directly.
- **Two-person rule for security code.** PRs touching `internal/egress`, `internal/engine/auth.go`, `secret.go`, `redact.go`, the secrets backend or API auth need approval from the *other* member.
- **`docker compose --profile tools run --rm test` must pass** before a PR.
- **No secrets anywhere in git:** not in configs, tests, Postman exports or docs. Real vendor tokens go only in Postman Vault / local env values and later the secrets manager. `.env` is gitignored.
- **No new third-party dependencies** without discussing it first (supply-chain risk).
- **Never log** tokens, auth headers, full URLs or response bodies. Use `engine.RedactURL`.
- **Never** set `InsecureSkipVerify`, never follow redirects, never bypass `egress.Policy.Client`.

---

## Target integrations

The platform must be **generic**. These are the integrations it needs to support:

| Category | Tools |
|---|---|
| SIEM / analytics | Elastic Security, Seceon, Gurucul, ManageEngine Log360, LogRhythm, OpenText ArcSight, Binary Search (to confirm which product), Palo Alto Cortex XSIAM |
| EDR / XDR | Sophos Intercept X, Kaspersky EDR, Seqrite XDR, Trellix EDR, Trend Micro Vision One, Symantec Endpoint Security |
| DLP | Forcepoint DLP, Symantec DLP, Digital Guardian, Trellix DLP, Zscaler DLP, Netskope DLP, Safetica |
| Firewall | Fortinet FortiGate, Check Point, Cisco Secure Firewall, SonicWall, Sophos Firewall, Juniper SRX, WatchGuard Firebox |
| Cloud security | AWS Security Hub / GuardDuty, Google Security Command Center, Wiz, Prisma Cloud, Orca Security, Lacework FortiCNAPP, CrowdStrike Cloud Security |

**Not yet supported by the engine, and needed for this list** (analysis in progress, each must be verified against vendor docs):

- **Auth:** session login (login → token/cookie), token returned in a response header, custom header prefixes, request signing (AWS SigV4, hashed nonce keys), signed-JWT OAuth (Google), runtime region discovery, mTLS, multi-host OAuth (token host ≠ API host).
- **Requests:** POST-based reads/searches, GraphQL, two-step fetches (IDs then details), async search jobs (submit → poll → fetch).
- **Pagination:** next URL or token in the response body, `search_after` / point-in-time.
- **Formats:** XML, NDJSON, CSV.
- **Transport:** many firewalls and on-prem SIEM/DLP tools mainly **push syslog/CEF/LEEF** rather than offer a pull API, and sit on private networks. This likely needs an **on-prem collector** plus an inbound log receiver: a major architecture addition, still to be designed.
- **On-prem TLS:** self-signed certificates need per-connector CA or fingerprint pinning (never "skip verify").

---

## Documents

| Doc | What's in it |
|---|---|
| [docs/WORK_SPLIT.md](docs/WORK_SPLIT.md) | Decisions, phase plan, Member A/B tasks, done checklist, FR coverage |
| [docs/REQUEST_SIDE.md](docs/REQUEST_SIDE.md) | Every file and function on the request side |
| [docs/MEMBER_B_HANDOFF.md](docs/MEMBER_B_HANDOFF.md) | Contracts, integration code and security rules for Member B |
| [docs/architecture.svg](docs/architecture.svg) | Target single-tenant AWS architecture |
| [PRD.md](PRD.md) | Detailed requirements |
