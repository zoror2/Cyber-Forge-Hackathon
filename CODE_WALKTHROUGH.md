# Explain the combined Go code

“One engine fetches different APIs using configuration. We map their records
into a common format and save them without duplicates. Each customer can access
only their own configs, data and secrets. A broken row gets a rejection reason;
a broken request gets a failed run.”

## Follow one run

1. `POST /configs` checks a JSON config and stores a draft revision. Tenant
   identity comes from the caller's API-key hash, not the JSON.
2. Activation selects the live revision. A new draft never changes a running
   connection automatically.
3. `POST /connectors/{id}/run` passes only the connector ID to `runner.Run`.
   It takes the tenant/connector database lock and loads the live DB config.
4. Member A's `engine.Fetch` makes guarded HTTPS requests, applies auth,
   retries temporary failures and follows the configured pagination style.
5. Each page goes to `mapping.Map`. It finds nested fields, renames/converts
   values, checks the typed User/Device/Event, and adds tenant/source/fetch time.
6. `Scope.SavePage` upserts valid records and stores minimal quarantine reasons
   in a short transaction. Network waits never hold these transactions open.
7. `Scope.FinishRun` records counts/outcome. Health shows failed/partial/bad-row
   states honestly. Repeating the sync updates the same stable record keys.

The local TLS mock has 25 synthetic users over three pages. Running twice keeps
25 rows. Its malformed response accepts two rows and quarantines two; the null
optional email is valid, while a missing ID or invalid date is rejected.

## Files and functions in simple terms

| File | Purpose |
|---|---|
| `cmd/api/main.go` | Connects the restricted DB role, secrets, engine, scheduler and protected API |
| `cmd/bootstrap/main.go` | Operator command for migrations, initial tenant and hashed API key |
| `cmd/mockvendor/main.go` | Starts the synthetic vendor, optionally with TLS |
| `cmd/devcert/main.go` | Generates the local mock certificate; production never trusts it implicitly |
| `internal/engine/spec.go` | Member A's request/auth/pagination config and validation |
| `internal/engine/engine.go` | Makes requests, retries, enforces limits, decodes JSON and emits pages |
| `internal/engine/auth.go` | Attaches a tenant's host-bound credential; caches OAuth tokens in memory |
| `internal/engine/secret.go` | Secret wrapper that cannot print its value; tenant-aware backend interface |
| `internal/engine/redact.go` | Removes URL credentials/query strings from errors and logs |
| `internal/egress/egress.go` | Checks URL shape, real destination IP and exact secret host; refuses redirects |
| `internal/app/policy.go` | Allows explicit TLS mock access in dev and rejects dev overrides in production |
| `internal/mockvendor/mockvendor.go` | Reusable synthetic paging/auth/failure handlers |
| `pkg/config/config.go` | Adds strict JSON, mapping, schedules and record budgets to A's contract |
| `pkg/model/records.go` | Defines User, Device, Event, rejection and run shapes |
| `pkg/mapping/mapping.go` | Follows paths, transforms values and validates a row |
| `internal/store/migrations/001_initial.sql` | Creates tenant tables, RLS policies, indexes and narrow helper functions |
| `internal/store/store.go` | Scoped transactions, config versions, locks, upserts, history/health and recovery |
| `pkg/secrets/secrets.go` | Resolves only the authenticated tenant's secret and returns A's safe wrapper |
| `pkg/secrets/local.go` | Development encryption with a different AES key per tenant |
| `pkg/secrets/aws.go` | Same interface using tenant-prefixed AWS secrets and tenant-specific KMS keys |
| `internal/runner/runner.go` | Coordinates pages → mapper → store and tenant-aware scheduling |
| `internal/api/api.go` | Authenticates every route and exposes only tenant-scoped operations |
| `internal/testutil/postgres.go` | Creates disposable test schemas and restricted DB roles |
| `tests/integration_test.go` | Exercises actual TLS requests, API, mapper, secrets and PostgreSQL together |
| `*_test.go` beside packages | Focused validation, encryption, egress, request and isolation tests |
| `pkg/mapping/testdata/events.json` | Synthetic date/nested-field/missing-ID fixture |
| `configs/*.json` | Declarative sample configs; fixture.invalid is test-only; mock_users runs locally |
| `postman/*.json` | Request scenarios and blank credential placeholders |
| `scripts/dev-env.ps1`, `load-env.ps1` | Generate private dev settings and load selected process variables |
| `scripts/smoke.ps1` | Drives the compiled/native or Compose API through the local demo |
| `scripts/check.ps1` | Blocks pushing until formatting, vet, race tests and builds pass |
| `Dockerfile`, `docker-compose.yml` | Package binaries and configure local services/test network |
| `go.mod`, `go.sum` | Dependency versions and checksums; request engine remains standard library only |
| `.gitignore`, `.dockerignore`, `.gitattributes` | Exclude private/runtime files and keep text formatting consistent |
| `.env.example` | Documents settings with empty credential values |
| `docs/WORK_SPLIT.md`, `MEMBER_B_HANDOFF.md`, `REQUEST_SIDE.md` | Team ownership, shared contracts and request-side detail |
| `docs/MEMBER_B.md` | Current integration/test evidence and boundaries |
| `docs/architecture.svg` | Original architecture reference; the text handoff contains the later tenant decision |
| `PRD.md`, `README.md`, this file | Product history, current setup and this explanation |

## Questions judges may ask

- **Why no duplicates?** Unique tenant/source/external-ID keys and SQL upsert.
- **Can one tenant choose another tenant in JSON?** No; that key is rejected and
  tenant identity comes from authentication. PostgreSQL RLS enforces it again.
- **Where is a secret?** In the tenant's encrypted backend, referenced by name
  in the config. The API never returns its value.
- **What changes for a new supported API?** Its JSON config and credential setup.
  A protocol/auth type the engine lacks still needs code.
- **What have we proved?** The tested local capability set and failure cases.
  Synthetic tests do not prove live vendor access, cloud security or capacity.
## KEV and AI additions

For the new mentor demo, use [docs/KEV_AND_AI.md](docs/KEV_AND_AI.md).

| File | Simple explanation |
|---|---|
| `internal/aidraft/source.go` | Loads public vendor descriptions that an engineer reviewed. |
| `internal/aidraft/groq.go` | Sends that public description to Groq with the private server key. |
| `internal/aidraft/draft.go` | Checks the AI's mapping and builds a bounded, inactive config. |
| `internal/api/draft.go` | Handles consent, quotas, audit and testing a saved draft. |
| `internal/app/ai.go` | Enables AI only for explicitly selected tenants. |
| `internal/store/ai.go` | Counts daily AI calls and stores audit metadata. |
| `internal/store/exposure.go` | Matches KEV vendor/product names to a customer's connected tools. |
| `internal/api/exposure.go` | Returns those matches through the authenticated API. |
| `002_exposure.sql` | Adds credential IDs/owners and the reviewed name lookup table. |
| `003_ai_drafts.sql` | Adds tenant-separated AI usage and audit tables. |
| `public_sources/*.json` | Public vendor facts and invented examples the AI may read. |
| `scripts/draft-config.ps1` | Downloads the proposed config to a local JSON file. |
| `scripts/test-draft.ps1` | Saves/tests the reviewed draft without turning it on. |
| `postman/ConfigBridge.KEV-AI.collection.json` | Clickable demo requests for the new flow. |

`pkg/config`, `pkg/model` and `pkg/mapping` now keep event vendor/product and trim
dirty names. `pkg/secrets` preserves encrypted legacy values while adding stable
IDs, authenticated ownership, multiple fields and exact host lists. The runner
can sample an exact draft revision without writing production records.

Mentor explanation: “Mohit fetches the feed. Our mapper keeps the vendor and
product, and SQL finds connected tools worth checking. AI helps write a new
integration config using public examples. We review and test the draft before
activation; credentials are entered locally.”
