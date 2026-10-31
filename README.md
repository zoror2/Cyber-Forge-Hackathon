# ConfigBridge — Go engine and API

ConfigBridge reads declarative integration configs, maps JSON into common User,
Device and Event records, and stores results centrally. The current team plan is
[WORK_SPLIT.md](docs/WORK_SPLIT.md). Prajwal owns **Member B: data + API**;
Mohit owns Member A's HTTP, authentication, retries, pagination and egress guard.

This branch replaces the earlier Python/SQLite slice with Go/PostgreSQL. It
implements the Member B side and provides an explicit offline fixture adapter.
The production request adapter deliberately returns `request_engine_not_connected`
until Member A's implementation is wired in. No live vendor or AWS deployment is
claimed. The static mock-vendor container is not Member A's failure simulator.

## Local setup (Windows PowerShell)

Install Go 1.26 or newer and Docker Compose. This branch was built with Go 1.27.3;
dependency versions and checksums are recorded in `go.mod` and `go.sum`.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/dev-env.ps1
docker compose up --build -d
powershell -ExecutionPolicy Bypass -File scripts/smoke.ps1
```

`dev-env.ps1` generates development credentials into the ignored `.env` file
without printing them. Preserve its master key: losing it makes locally stored
vendor secrets unreadable. `.env` is a plaintext local file protected by your
filesystem permissions. Compose binds published ports to the loopback interface.
Its PostgreSQL connection uses unencrypted transport on the local Docker network;
production requires TLS and deployment hardening from Member A's phase 2 work.

The smoke script submits the fixture config through the API, validates and
activates its revision, tests it without writes, then runs it twice. Each run
receives four synthetic records, accepts three and quarantines one missing its
ID. The database retains three unique events. Quarantine keeps one reason per
rejection per run, so two runs produce two quarantine entries. Runs are labelled
`mode: fixture`; a quarantined row makes health `degraded`.

To use your own PostgreSQL instead of Docker, export `DATABASE_URL`,
`CONFIGBRIDGE_ADMIN_TOKEN` (at least 32 characters), `CONFIGBRIDGE_MASTER_KEY`
(base64 of 32 random bytes), and `CONFIGBRIDGE_FIXTURE_MODE=1` in the process
environment, then run `go run ./cmd/configbridge`. The binary does not load `.env`
automatically. Default listen address: `127.0.0.1:8080`.

## API and Postman

Import both JSON files under [postman/](postman/). Set `admin_token` using a local
Postman value; do not sync or export populated environments. Use Postman Vault for
`vendor_token` before calling the optional provision-secret request. All requests
inherit `Authorization: Bearer {{admin_token}}`. Every endpoint, including health
and unknown paths, refuses missing/incorrect authentication. Browser cross-origin
requests are rejected. The HTML health view also needs the Authorization header
(use the Postman HTML request or an authenticated HTTP client).

| Method / route | Action |
|---|---|
| `POST /configs` | Accept one YAML/JSON config; store a new draft revision |
| `POST /configs/{id}/validate` | Validate latest stored revision; return errors only |
| `POST /configs/{id}/activate` | Body `{"revision":1}`; make this validated revision live |
| `PUT /secrets/{name}` | Body `{value,allowed_host}`; return 204 with no body |
| `GET /secrets` | Names, allowed hosts, backend and dates only |
| `POST /connectors/{id}/test` | Read live config; check one page/100-row sample without writes |
| `POST /connectors/{id}/run` | Read live config; execute synchronously and return run result |
| `GET /runs?connector=` | Run history |
| `GET /health` | JSON health, or HTML with `Accept: text/html` |
| `GET /records/{users\|devices\|events}?source=` | Common normalized records |
| `GET /quarantine?connector=` | Field-level rejection metadata |

Runs and tests have empty request bodies. Neither accepts a URL, file path or
config body. Only a `live` database config can run. A new draft does not replace
the current live revision until activation. Activating while that connector runs
returns 409. Phase 1 has admin-token activation; independent-person approval and
SSO belong to phase 2. List endpoints accept `limit` (1–500) and nonnegative
`offset`; defaults are 100 and 0. A busy connector or full worker capacity returns
409. A failed collection returns 502 (503 if the request engine is unavailable).

## Tests

```powershell
go test ./...
# Use a disposable PostgreSQL database whose user can create test schemas:
$env:TEST_DATABASE_URL = $env:DATABASE_URL
go test ./... -count=1
go vet ./...
```

Without `TEST_DATABASE_URL`, database integration tests explicitly skip. With it,
each test creates its own random schema, applies migrations and removes only that
schema at cleanup. The integration tests cover the full authenticated API flow,
upserts, quarantine, config revisions, source isolation, secrets, locks, partial
failures, limits, recovery, and two accelerated scheduled runs. See
[docs/MEMBER_B.md](docs/MEMBER_B.md) for measured evidence and remaining work.

## Security and integration boundaries

- Local secrets are encrypted with AES-256-GCM in PostgreSQL using an external
  master key. Name-bound authenticated encryption rejects ciphertext copied to
  another secret. Secret objects redact ordinary formatting and JSON output.
- `CONFIGBRIDGE_SECRETS_BACKEND=aws` uses the AWS SDK credential chain and stores
  an envelope at `configbridge/{name}` in Secrets Manager. Unit tests use a fake
  SDK client; live AWS access is unverified. Phase 1 provisioning needs write
  permission; phase 2 must separate provisioning from a read-only runtime role.
- API rotation can change a value but cannot change its host or backend binding.
  If backend storage succeeds and metadata commit fails, provisioning reports
  failure; an orphan backend value may need operator reconciliation. No secret
  value is exposed to fix this through the API.
- The config validator rejects literal credentials in headers/credential-named
  query parameters, private IP literals, HTTP, embedded URL credentials and
  unsupported keys. **DNS resolution, connection-time destination checks, host
  binding enforcement before requests and redirects are Member A's work.** The
  current config checks alone do not establish complete SSRF prevention.
- Quarantine stores index, field and a fixed reason, never raw vendor payloads.
  API errors omit raw database/provider exceptions. HTML escapes source content.
- Scheduling uses two workers and a queue of ten. A due item left out of a full
  queue remains due. Manual runs use the same capacity and PostgreSQL connector
  lock. Lock-connection loss cancels the job; stored run status fences abandoned
  workers. Recovery marks only unlocked abandoned runs interrupted.
- Incremental sync is not enabled; `sync_state.watermark` is reserved and never
  advanced. A clean success updates `last_success`; quarantined or failed runs
  do not. Schedules use the interval after completion and start due on activation.

## FR traceability

| ID | Current implementation / evidence | Remaining dependency |
|---|---|---|
| FR-1 | Auth config contracts in [config.go](pkg/config/config.go) | Member A handlers and live evidence |
| FR-2 | Strict GET/URL/params config and [config tests](pkg/config/config_test.go) | Actual requests: Member A |
| FR-3 | Pagination contract and validation | Member A paging algorithms/tests |
| FR-4 | [scheduler](internal/engine/engine.go), PostgreSQL locks, [integration tests](tests/integration_test.go) | Real-provider scheduling after adapter wiring |
| FR-5 | [mapper](pkg/mapping/mapping.go), [mapping tests](pkg/mapping/mapping_test.go) | None for tested transforms |
| FR-6 | [secrets](pkg/secrets/), [API](internal/api/api.go), encryption and metadata-only tests | Member A egress/redaction review; live AWS |
| FR-7 | Typed safe failure contract | Member A retry implementation/tests |
| FR-8 | Rate-limit failure category in health | Member A Retry-After timing and persistent retry eligibility |
| FR-9 | Mapper quarantine + [page transactions](internal/store/store.go), integration tests | Member A response parsing |
| FR-10 | Authenticated JSON/escaped HTML health, integration tests | UI/SSO: phase 2 |
| FR-11 | [Postgres migration](internal/store/migrations/001_initial.sql), typed models, upserts and integration tests | Live provider evidence |

For the short file/function explanation, read [CODE_WALKTHROUGH.md](CODE_WALKTHROUGH.md).
