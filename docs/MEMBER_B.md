# Member B integration record

Branch: `member-b`. Integrated Member A's main commit
`d0bbe2f2f25279e91143cbda3aa2e45b9b68d97e` before adapting the data/API features.
Current contracts are in [MEMBER_B_HANDOFF.md](MEMBER_B_HANDOFF.md), especially
multi-tenancy in §2.6. The earlier single-tenant Member B implementation is
superseded by the integration described here.

## Feature order and evidence

| Stage | Local verification | Result |
|---|---|---|
| A baseline | Isolated checkout of `d0bbe2f`: all request/egress tests + vet | Passed before merge |
| Config + mapper | A request structs, strict JSON, nested/array paths, UTC/date precision, enums, defaults, exact numeric IDs | Passed alongside A tests |
| All entity tables | Actual offset paging into Events with a non-ISO date/lookup, plus Device mapping and upsert | Passed against PostgreSQL |
| PostgreSQL | Fresh isolated schemas and restricted login roles; migrations, tenant keys, RLS, cross-tenant inserts/updates, pooled-session cleanup, upserts | Passed against PostgreSQL 16.9 |
| Secrets | Two tenant keyrings, name/tenant AAD, ciphertext/tampering, same-name isolation, rotation/binding refusal, AWS tenant namespace + KMS fake client | Passed; no live AWS claim |
| API + real fetch | Actual TLS HTTP client → A engine → mapper → PostgreSQL → HTTP API | Passed for both tenants |
| Failure handling | 401 no retry storm; API-key/Basic/Bearer/OAuth; 500 recovery/exhaustion; 429 wait/delay cap; timeout; redirect; huge/invalid/trailing body; off-host link; cut connection; page/record limits | Passed |
| Lifecycle | Draft vs live revisions, activation refusal during a lock, test without writes, source/provenance, quarantine, HTML escaping, body/list limits | Passed |
| Scheduling/recovery | Tenant A locked while B progresses; independent tenant locks, two scheduled runs each, disable, recover abandoned work, fence stale writers | Passed |
| Native smoke | Built bootstrap/API/TLS mock. Three pages, 25 accepted, 25 unique after repeat; malformed endpoint accepted two/quarantined two | Passed |
| Final local gate | Formatting + vet + `go test -race -count=1` with actual PG + all native builds | Passed |

The final parallel run exposed a cross-schema advisory-lock collision. Lock
names now include application schema + tenant + connector (and purpose), with
a dedicated regression test proving schema and tenant independence. The push
gate was rerun after that correction; earlier passing runs were not used to
override the failure.

Native machine: Windows/amd64, Go 1.27.3, PostgreSQL 16.9, portable GCC 16.2.0 for
the race detector. Inputs are synthetic. Local database credentials, generated
keys, reports and installed tools remain ignored and are not part of the PR.

Postman collection execution through Newman: **44 requests, 44 assertions,
zero failures** against the compiled native API/TLS mock/PostgreSQL stack.
This included core routes, failure scenarios, cross-tenant 404s and write-only
secret provisioning. Vault substitution used an ignored local copy with a
synthetic mock credential; no populated environment was committed.

Gitleaks staged-source scan: **zero leaks**. Compose configuration/environment
validation: passed. Linux/amd64 static builds for all commands: passed.

Docker container startup, real vendor accounts, real AWS
access, deployment and throughput measurements remain unverified.

## What changed during integration

- Preserved A's request engine and egress guard. Moved our lifecycle coordinator
  into `internal/runner`; deleted the parallel collector/offline stub.
- Adopted module `configbridge`, JSON configs and A's request/paging/auth fields.
  Removed YAML parsing and its dependency. The CLI binary is now `cmd/api`.
- Replaced the global admin token with DB-hashed tenant API keys. Tenant identity
  comes only from authentication. Configs, secrets, caches, records, history,
  quarantine, scheduler jobs and locks all carry tenant scope.
- Split DB migration/provisioning from the runtime role. Forced RLS covers all
  customer tables; operational `schema_migrations` is not customer data. Narrow
  security-definer functions authenticate hashes and list only job identities.
- Replaced the shared local master key with distinct development keys per tenant.
  AWS names and configured KMS bindings are tenant-specific; no runtime API can
  rebind a secret to another host/backend or choose another tenant.
- Extracted the existing synthetic vendor handlers for reuse in integration
  tests, and added optional TLS startup. This keeps A's HTTPS validator intact.
  Mock retry counters use `scenario_id`, since credential-like `key` params are
  correctly rejected by A's config validator.
- Added request attempt counts to A's result; rejected trailing JSON after a
  successful decode; removed untrusted OAuth token-type values from errors.
- Kept quarantine metadata-only, following the PRD's safer option. The handoff's
  optional raw-record copy is omitted to avoid persisting unknown credentials or
  PII. This is an explicit scope choice, not a claim of a raw-payload recovery UI.

## Important remaining boundaries

- Result attempts count logical API attempts, including retries, not separate
  OAuth token exchanges. Partial runs retain already committed pages and report
  incomplete outcomes. Only clean successes update `last_success`; no watermark
  is advanced.
- Retry-After timing is tested. Persisting a server's next eligible retry time
  across process restarts is still a shared extension; it is not implemented.
- AWS SDK behavior is tested through a fake client with actual PostgreSQL tenant
  metadata. IAM permissions, KMS configuration and live AWS access need separate
  verification. Phase 2 must separate provisioning from read-only runtime IAM.
- The local schema is for the Go implementation; it is not an in-place migration
  of old Python SQLite data or an earlier development DB. Use a fresh dev DB.
- `data/` contains temporary local test artifacts only. The PR has no Python
  runtime files. A diff may show deleted Python paths until this branch merges.

## Reproduce the local gate

```powershell
$env:TEST_DATABASE_URL = $env:MIGRATION_DATABASE_URL
.\scripts\check.ps1
```

The test DB account must be able to create temporary schemas and restricted test
roles. The application itself always connects as the restricted runtime role.
Test schemas/roles are scoped to each test and cleaned up afterward.

Security-sensitive changes remain subject to cross-review before merge. This
branch updates PR #4 only; it does not merge or publish the application.
