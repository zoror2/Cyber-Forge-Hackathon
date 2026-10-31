# Prajwal — Member B delivery and Member A handoff

Branch: `member-b` (previously `prajwal/go-phase1`), based on main at
`eac038711220e683bb32d7865c0fd50e483292c4`.

The user confirmed Prajwal is **Member B (data + API)**. The authoritative split
is [WORK_SPLIT.md](WORK_SPLIT.md). That document supersedes the earlier PRD's
Python, SQLite and unauthenticated-local-interface choices. Mohit's architecture
diagram and work-split document are preserved.

## Delivery status

| Task | Delivered | Verification / remaining work |
|---|---|---|
| B1 Config contract | Strict Go YAML/JSON models, defaults and semantic errors | Tests cover unknown/duplicate keys, custom tags, invalid URLs, credential fields, transforms, timezone, auth and paging fields. Shared contract needs Member A review. |
| B2 Mapping | User/Device/Event, nested paths and array indices, defaults, scalar/lookup/date transforms, UTC and date precision, metadata-only quarantine | Unit tests and four-row PostgreSQL/API flow; no invented missing user/device fields. |
| B3 PostgreSQL | Embedded versioned migration, config revisions, metadata, common entity tables, quarantine, runs, sync state, upserts and recovery | Actual PostgreSQL 16.9 integration tests, including source isolation and abandoned-worker fencing. Watermarks remain unused. |
| B4 Secrets | AES-256-GCM local development backend + AWS SDK backend behind the same interface; immutable API host bindings, metadata-only reads | Local encryption/tampering/API tests and mocked AWS create/rotate/read tests. Live AWS is unverified. Member A must cross-review this security-sensitive code. |
| B5 Scheduling | Two workers, bounded queue, cross-process PostgreSQL connector locks shared with manual runs, due check inside the lock, clean cancellation | Two accelerated 1-second scheduled runs; overlapping run and activation refusal; disabled-schedule check. |
| B6 API + health | All planned routes, admin token on every route, bounded inputs/lists, escaped health HTML | Auth tests and real HTTP/DB integration flow. Member A must cross-review authentication. |
| B7 Postman | Importable collection and blank-secret local environment | JSON artifacts checked; collection not executed in the Postman app. PowerShell smoke and Go HTTP integration tests exercise the same routes. |
| B8 Compose | PostgreSQL + engine + static mock-vendor service, nonroot application container, loopback published ports | Docker is unavailable on this machine, so the Compose build/start remains unverified. The compiled native app is tested separately. Member A owns the richer failure simulator. |

## Contracts for Mohit

### Request engine integration

Implement `pkg/collector.Fetcher`:

```go
Fetch(ctx context.Context, cfg config.Config, emit func(collector.Page) error) error
```

`Page.Payload` is the decoded JSON response (`map[string]any` / `[]any`), not an
already-normalized record list. `mapping.Items` extracts `response.items_path`.
Use `json.Decoder.UseNumber()` when preserving large numeric IDs. `Page.Attempts`
counts HTTP attempts for that emitted page. The current count cannot include
failed attempts that never emit a page; extend the result contract together if
full failed-attempt metrics are needed.

Call `emit` sequentially and stop immediately on its error. Return only after the
configured collection is exhausted. Respect context cancellation and enforce
response bytes, HTTP timeout, retry budgets and destination policy before and
while fetching. The runner independently enforces page/record/run limits and
stores each accepted page in a short transaction.

Wire the production adapter in `cmd/configbridge/main.go` where
`collector.Unavailable{}` is currently selected. Pass `secretService` as the
`pkg/secrets.Reader`; do not expose the writable service to HTTP auth handlers.
The engine entry point accepts only a connector ID and always loads a `live`
database revision. `test` uses the same rule, stops after one page/100 rows and
does not save production records, run history, quarantine or sync state.

Allowed failure codes are defined in `collector.Category`; arbitrary provider
errors are reduced to `collection_failed`. Never put a URL, response body, header
or secret value in a public error. `collector.Failure` intentionally prints only
a fixed message. Persistent 429 eligibility/`next_retry_at` still needs a shared
contract and migration with Member A; do not claim that part of FR-8 complete.

### Config details

The structs in `pkg/config` are the proposed shared Phase 1 contract. Sample:
`configs/fixture_events.yaml`. Config schema `version: 1` is separate from the
database revision number returned by `POST /configs`.

- GET/HTTPS only. Query values use `request.params`; URLs themselves cannot carry
  credentials, a query string, or a fragment.
- Auth types: `none`, `api_key`, `basic`, `bearer`, `oauth2_client_credentials`.
  Credential references use `auth.secret_name`, not the old Python `secret_env`.
- Basic and client-credentials secrets are strings; agree their JSON envelope
  shape in Member A's handler before live setup. The secrets backend treats the
  value as opaque and does not guess how credentials are split.
- A secret includes an exact lower-case `allowed_host`. The request engine must
  compare that binding to every credential-bearing destination, including OAuth
  token requests. Do not forward a secret to another host.
- Pagination types: `none`, `next_link`, `offset`, `page_number`, `cursor`.
- Date layouts use Go layouts (`2006-01-02`, `02/01/2006 15:04`), not `%Y-%m-%d`.
  Naive dates require an IANA timezone. Dates with an explicit offset normalize
  directly to UTC. Date-only Event timestamps retain `timestamp_precision`.
- Only `Accept` and `User-Agent` config headers are currently accepted. Member A
  can propose additional noncredential headers with validation tests.
- No request policy knob in a connector config can enable private-network access.
  DNS and connection-time checks remain Member A's responsibility.

### Database and lifecycle

Migration SQL lives with `internal/store` and is embedded in the binary. Migration
history and a PostgreSQL advisory lock make application startup repeatable.
`SaveConfig` writes a new draft revision and hash; `Activate` explicitly selects
one revision. There is at most one live revision per connector.

Records use `(source, external_id)` within separate `users`, `devices`, `events`
tables. Payload JSON is validated through common typed models before storing;
every record has `source` and UTC `fetched_at`. Rows reference their producing run.
Missing optional fields remain JSON null.

Run outcomes: `running`, `success`, `completed_with_errors`, `failed`,
`incomplete`, `interrupted`. Quarantined rows produce `completed_with_errors` and
degraded health. A failed later page may leave earlier pages committed, but the
run is incomplete. Only a clean success updates `sync_state.last_success`.
No watermark is advanced by this branch.

Connector session locks use dedicated pool connections. Heartbeats cancel a run
if that session is lost; database run-status checks also fence an abandoned
writer after recovery/replacement. Startup recovery takes each connector lock
before marking its abandoned runs interrupted. A healthy run in another process
is left alone. This expects direct/session-based PostgreSQL connections; do not
put transaction-mode PgBouncer in front of session advisory locks.

## Measured evidence (31 October 2026)

- Official Go archive checksum checked; toolchain reports `go1.27.3 windows/amd64`.
- Temporary PostgreSQL reports `16.9` and listens on loopback port 55432. Test
  schemas are random and isolated; this is synthetic local verification.
- `go test ./... -count=1`: passed, including four real PostgreSQL integration
  tests. They exercise authenticated HTTP requests, fixtures, uniqueness,
  quarantine, secret ciphertext/rotation, config versions, source isolation,
  locks, partial failure, limits, scheduling and restart recovery.
- `go vet ./...`: passed.
- `go build -o bin/configbridge.exe ./cmd/configbridge`: passed.
- Compiled native server + `scripts/smoke.ps1`: passed. The actual HTTP flow
  submitted/activated the fixture revision, tested it without writes, ran it
  twice, and confirmed three unique database events. Both runs accepted three
  and quarantined one. Startup log contained only the labelled fixture mode and
  authentication requirement.
- Postman artifact parsing: passed (14 requests, six environment variables;
  credential values empty). `git diff --check`: passed.

Not verified: live GitHub/Jira/NVD/Okta/CISA collection, real AWS Secrets Manager,
Docker image/Compose execution, a Postman-app run, throughput benchmark or a
60-second live-provider schedule. Phase 1 as a whole is not complete.

## Cleanup

Removed the obsolete Python package, Python package specification and Python
test. Moved the synthetic JSON to Go's embedded fixture directory and removed its
duplicate under `tests/fixtures`. Replaced Python setup/walkthrough text with Go
instructions. Kept the original product PRD with an explicit current-plan note,
plus Mohit's work split and architecture. Download archives and extraction
staging were removed; installed tools, caches, runtime databases and private
environment values remain ignored locally and must not be committed.

Cross-review requirement: Member A reviews B4 and B6 authentication before merge.
This branch must not be self-merged into main.
