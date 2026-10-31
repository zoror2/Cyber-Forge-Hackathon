# Explain the Member B code to judges

“Mohit's side obtains API responses safely. Our side checks the configuration,
converts each row into a common format, saves it in PostgreSQL, and exposes a
protected API to operate and inspect the integrations.”

## Follow one fixture run

1. Submit `configs/fixture_events.yaml` to `POST /configs`. `config.Decode` checks
   it; `Store.SaveConfig` saves revision 1 as a draft.
2. Activate that revision. `Store.Activate` makes it live. Sending a config
   directly to the run endpoint cannot bypass this step.
3. Call `POST /connectors/fixture_events/run`. `Engine.Run` takes a database lock,
   reloads the live config and creates a run record.
4. `Fetcher.Fetch` emits a page. The offline adapter emits four synthetic rows;
   Member A's adapter will emit actual API pages.
5. `mapping.Items` finds `vulnerabilities`. `mapping.Map` reads fields such as
   `dates.added`, converts the date to UTC and validates the common Event.
6. `Store.SavePage` upserts three good events and quarantines the missing-ID row.
   A second run updates the same source/ID keys, so only three events remain.
7. `Store.FinishRun` stores counts and `completed_with_errors`. `/health` shows
   degraded status. `/quarantine` explains the rejected field without raw data.

## What each file is for

| File | Plain explanation |
|---|---|
| `cmd/configbridge/main.go` | Reads environment settings, opens the DB, chooses the secret backend and starts API/scheduling |
| `pkg/config/config.go` | Shared structs, strict YAML/JSON reading and validation |
| `pkg/model/records.go` | Common User, Device, Event, rejection and run shapes |
| `pkg/collector/collector.go` | Small interface where Mohit plugs in his safe request engine |
| `pkg/mapping/mapping.go` | Finds nested values, renames fields, applies transforms and checks rows |
| `internal/store/migrations/001_initial.sql` | Creates the PostgreSQL tables and indexes |
| `internal/store/store.go` | Versions configs, locks connectors, upserts data and queries history/health |
| `pkg/secrets/secrets.go` | Host-bound secret interface, immutable bindings and metadata queries |
| `pkg/secrets/local.go` | Encrypts/decrypts local development secrets using an external master key |
| `pkg/secrets/aws.go` | Uses the same interface with AWS Secrets Manager |
| `internal/engine/engine.go` | Coordinates live config → pages → mapping → storage and scheduling |
| `internal/api/api.go` | Admin authentication and the Postman-facing routes |
| `internal/fixture/fixture.go` | Explicit offline adapter; produces synthetic data without HTTP |
| `internal/fixture/testdata/events.json` | Three good records and one missing its ID |
| `cmd/fixturevendor/main.go` | Serves that static JSON for development container wiring |
| `configs/fixture_events.yaml` | Instructions describing how to map the sample response |
| `pkg/*/*_test.go`, `internal/api/auth_test.go` | Focused config, mapping, secrets and authentication checks |
| `tests/integration_test.go` | Exercises API, mapper, scheduler and store together against real PostgreSQL |
| `postman/*.json` | Importable requests and an environment with empty credential placeholders |
| `scripts/dev-env.ps1` | Generates private local environment values without printing them |
| `scripts/smoke.ps1` | Repeats the fixture demo against the running API |
| `Dockerfile`, `docker-compose.yml` | Package/start the application, PostgreSQL and static mock vendor |
| `go.mod`, `go.sum` | Record dependency versions and checksums |
| `.gitignore`, `.dockerignore`, `.gitattributes` | Exclude private/runtime files and keep text formatting consistent |
| `.env.example` | Documents settings with empty credential placeholders |
| `docs/WORK_SPLIT.md`, `docs/architecture.svg` | Mohit's team plan and architecture; preserved |
| `docs/MEMBER_B.md` | Progress, integration contract, evidence and remaining work |
| `PRD.md`, `README.md`, this file | Product context, setup and this short explanation |

## Important distinctions

- Libraries provide YAML parsing, PostgreSQL access, encryption and AWS calls.
  Our code connects those pieces into a declarative integration lifecycle.
- Test connection checks a sample and writes no records, history or watermark.
- Quarantine means a row failed validation; a network failure fails the run.
- A partial run can retain earlier committed pages, but cannot claim success.
- The fixture proves our data/API flow. Actual vendors require Member A's request
  implementation and separate live verification.
