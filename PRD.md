# ConfigBridge

> Implementation update: the team has chosen **Go + PostgreSQL**, strict JSON
> configuration and tenant isolation for Phase 1. The updated multi-tenant
> contract is in [docs/MEMBER_B_HANDOFF.md](docs/MEMBER_B_HANDOFF.md), section 2.6.
> [docs/WORK_SPLIT.md](docs/WORK_SPLIT.md) is the current implementation plan;
> its language, database, API and ownership decisions supersede the earlier
> Python/SQLite implementation choices below. Keep this document for product
> requirements and acceptance criteria. Current Member B progress and handoff:
> [docs/MEMBER_B.md](docs/MEMBER_B.md).

## Product requirements and implementation context

Version: 1.0
Date: 31 October 2026
Team: npc
Members: Mohit Kumar M and Prajwal HM
Selected challenge: Config-Driven Generic Integration Platform — Add new tool integrations without writing code
Status: Implementation specification. Features and performance targets below are not claims of completed work.

## 1 Read this first

Build a configuration-driven security data integration platform for the CyberForge hackathon. The platform reads a YAML file, calls the configured API, collects every permitted page, converts records into a common schema, saves them, and shows the connection's health.

The core idea is **one reusable engine, one configuration per connection**. Do not create a GitHub-specific Python connector and a separate NVD-specific Python connector. Provider-specific URLs, field names, pagination parameters and constants belong in configuration. Python implements reusable capabilities such as Bearer authentication, offset pagination and date conversion.

A new source needs no engine change **when it uses capabilities the engine supports**. A genuinely new protocol or authentication mechanism may require extending that capability set. Do not claim compatibility with every API.

The current task is the integration platform. Autonomous pentesting, Hidden Wiki discovery, network scans, attack-path analysis and the earlier ComplySense certification project are outside this implementation. Do not reuse the supplied network clues as integration targets.

### Instructions for the coding assistant

1. Inspect the existing repository, its current branch and applicable `AGENTS.md` instructions first. Preserve teammates' changes. Adapt an existing working implementation before creating a parallel one.
2. Use this document as the product specification. The organizer's source PRD controls actual challenge requirements if there is a conflict. State any conflict clearly.
3. Start with Milestone 0, then Milestone 1. Complete, test and explain one milestone at a time. Continue the requested work without asking for approval for routine local edits.
4. Keep explanations short and simple. Prajwal must understand and defend the code. Explain the execution path, why each new module exists and the important failure cases. Do not give long tutorials or repeated quizzes.
5. Prefer ordinary functions and explicit data models. Avoid deep inheritance, unnecessary design patterns, generic plugin frameworks and large orchestration dependencies.
6. Never silently skip required features. Track FR-1 through FR-11 in the README with links to code and tests.
7. Do not fabricate successful API connections, credentials, test results or performance measurements. Label fixture, recorded and live runs distinctly.
8. Use fixtures to progress when credentials or external access are unavailable. Report the exact blocker for live verification. Fixture success does not satisfy the three-real-source requirement.
9. Do not ask for secrets in chat, place them in config files or echo them in terminal output. Use environment-variable references and a placeholder-only `.env.example`.
10. Do not push, merge, publish or modify external services unless the user's current instructions authorize that action. The project only reads source APIs.

## 2 Problem and intended users

Security teams collect data from many products. Each product uses different authentication, endpoints, pagination and response fields. Handwritten connectors repeatedly implement the same retry, scheduling and storage logic, and behave inconsistently when something fails.

The primary user is a security engineer or integration engineer who understands the source API well enough to describe it in configuration. An operator checks sync health and investigates errors. The hackathon release is a local, single-workspace application.

The product should make a supported new source configurable in under one hour, including mapping and a successful collection run. Measure onboarding time rather than claim it in advance.

## 3 Required scope and boundaries

### Required release

- At least three real sources on free access tiers, with varied authentication and paging behaviour.
- API-key authentication plus Bearer-token authentication. Also support unauthenticated public feeds.
- Two substantive pagination strategies: HTTP next-link pagination and offset pagination. Support no pagination for a single feed.
- Configurable endpoint, HTTP method, query parameters, collection interval and record mappings.
- Safe secrets, bounded retries, HTTP 429 handling, malformed-record quarantine, health reporting and persistent common-schema storage.
- A repeatable setup, runnable tests, sample configs and a clear README.

### Explicit implementation choices

- Begin with JSON REST APIs over HTTPS. The initial method is GET, explicitly declared in config. Reject unsupported methods clearly. The selected sources do not require write operations.
- One config describes one collection endpoint and one destination entity type. Multiple configs can describe different collections from the same provider.
- Support User, Device and Event/Alert record models. A source emits only the entity type it actually supplies. Do not invent device data or private user fields to populate a table.
- Read-only collection is sufficient. Ticket creation, external notifications and automated remediation are not prerequisites.
- A basic web health page is sufficient. Prioritize engine correctness over UI polish.
- No model training or LLM is required by the supplied integration PRD.

### Defer until the required release works

OAuth2, SOAP, GraphQL, binary protocols, multi-step login, a workflow canvas, Kubernetes, Kafka, enterprise multi-tenancy and cloud hosting. Do not advertise these as supported.

## 4 First task and milestone order

### Milestone 0 Repository and setup

Inspect existing files. Create the Python package, dependency specification, `.gitignore`, placeholder `.env.example`, sample-config directory and tests. Use a Python version available to both teammates, preferably 3.11 or 3.12. Record and lock dependency versions after verifying compatibility. Do not pin guessed versions.

Use Windows-compatible commands in the README. Keep runtime data in `data/`, excluded from Git. Add a brief progress checklist and this PRD to the project context if the user requests importing it.

### Milestone 1 The first working engine

Build only this complete flow:

1. Read and validate one YAML config.
2. Fetch one JSON response through an injectable HTTP client.
3. Locate the configured record array.
4. Map fields and validate the normalized records.
5. Store valid records and quarantine invalid ones in SQLite.
6. Print a concise run summary.

Use an offline HTTP fixture with four records: three valid records and one record missing its required ID. Include a nested field and a date in the fixture. The first run should store three records and quarantine one. Repeating the run must keep three unique records rather than inserting three duplicates. These are fixture expectations, not live results.

Then verify the same flow with one real public feed, preferably CISA KEV. Do not add pagination, scheduling, an LLM or a dashboard before this slice works.

**Milestone 1 completion:** a documented CLI command runs the config, SQLite contains the expected records, the invalid record has an actionable quarantine reason, and repeat runs do not duplicate data.

### Milestone 2 Shared request handling and pagination

Add API-key and Bearer authentication, next-link and offset pagination, timeouts, retries, rate-limit handling and request destination restrictions. Test them against deterministic local HTTP responses before relying on real providers.

### Milestone 3 Three real sources

Verify the selected providers and capture live-run evidence. Keep provider variations in YAML. Make at least one live paginated run traverse two pages. Use a narrowly filtered collection and a small permitted page size rather than downloading an entire vulnerability database.

### Milestone 4 Scheduling and health

Add the bounded background runner, scheduling, persistent run history and a basic health page. Manual runs and scheduled runs must use the same engine.

### Milestone 5 Failure demonstrations and benchmark

Prove recovery from 500, timeout and 429 responses; quarantine bad records; demonstrate missing secrets and failed authentication without leaking them. Run a local load benchmark and report actual results.

### Milestone 6 Selected bonus features

Complete B-2 config validation and B-3 test connection first. Add B-1 incremental sync if the selected source semantics support it. Consider a config-generating form or AI assistant only after the core acceptance checklist passes.

## 5 Requirement traceability

The following IDs come from the organizer's PRD. Implementation details and acceptance tests are project decisions.

| ID | Required behaviour | Acceptance evidence |
|---|---|---|
| FR-1 | API key and at least one other authentication type | Header-key and Bearer fixtures verify the exact request; missing and invalid credentials are handled safely. |
| FR-2 | Config describes URL, method and query parameters | Changing these supported values changes the outgoing request without editing engine code. GET is the initial supported method. |
| FR-3 | At least two pagination styles | Next-link and offset tests each collect multiple pages with correct termination. |
| FR-4 | Configurable collection schedule | A short test interval triggers a run; disabling a connection stops future automatic runs. |
| FR-5 | Rename fields, select nested values and convert dates | Mapping tests cover all three operations plus missing optional and required values. |
| FR-6 | Safe secret storage and handling | Configs contain environment names only; sentinel credentials never appear in captured logs, errors, reports or database records. |
| FR-7 | Retry timeouts and 5xx with backoff | A deterministic failure-then-success test records attempts and bounded waits; exhausted attempts produce a failed run. |
| FR-8 | Respect 429 and Retry-After | Tests verify seconds and HTTP-date forms, including a delay that exceeds the remaining run budget. |
| FR-9 | Skip or quarantine bad records without crashing a run | Mixed valid/invalid records preserve valid results and record field-level error reasons. |
| FR-10 | Per-connection health | Page shows current status, last run, last success, accepted records and sanitized last error. |
| FR-11 | Store results centrally in a common schema | SQLite contains validated normalized records with source and fetched_at; repeat syncs upsert correctly. |

| Bonus ID | Plan | Acceptance evidence |
|---|---|---|
| B-1 | After the required release | An incremental-enabled source uses a committed watermark and can resume without losing records after failure. |
| B-2 | High priority | Invalid config fails before network access and points to the failing key. |
| B-3 | High priority | A test command makes a bounded connection check without inserting production records or advancing the watermark. |
| B-4 | Implemented locally | Opt-in email alerts use an operator-routed, tenant-isolated outbox; verified with a loopback capture, not an external mailbox. |
| B-5 | Implemented locally | The development web form generates, downloads, saves and tests drafts through shared validation. See docs/BONUS_B4_B5.md. |

## 6 Proposed technology and small module structure

Use Python, HTTPX, Pydantic, PyYAML and the standard-library `sqlite3` module. Add FastAPI and Uvicorn when the API/health milestone begins. Use pytest with HTTPX's mock transport or an equivalent deterministic test seam. Use maintained releases, inspect installed versions and lock what has actually been tested.

Keep one application process for the hackathon. Use a small bounded worker pool for sync jobs. Do not add a distributed queue unless a measured need justifies it.

```text
PRD.md
README.md
pyproject.toml
.env.example
.gitignore
configbridge/
  __init__.py
  schemas.py
  config.py
  http_client.py
  mapping.py
  store.py
  runner.py
  cli.py
  app.py
configs/
  cisa_kev.yaml
  github_issues.example.yaml
  nvd_cves.example.yaml
tests/
  fixtures/
  test_config.py
  test_mapping.py
  test_http.py
  test_runner.py
  test_store.py
scripts/
  benchmark.py
data/                       # ignored runtime output
```

Do not create empty modules merely to match this tree. Introduce them when their milestone requires them. A small UI can be served by `app.py` with a template or static assets. Keep UI code separate from engine functions.

| Module | Responsibility | Explanation for Prajwal |
|---|---|---|
| schemas.py | Typed config and record models | Defines what a valid config and record look like. |
| config.py | Safe YAML loading and semantic checks | Reads the instructions and catches mistakes. |
| http_client.py | Destination policy, credentials, HTTP and retry handling | Makes requests safely and consistently. |
| mapping.py | Paths, whitelisted transforms and record validation | Converts different response formats into ours. |
| store.py | SQLite records, run history, quarantine and checkpoints | Saves results and avoids duplicates. |
| runner.py | Run lifecycle, page loop, scheduling and concurrency | Coordinates the steps in the correct order. |
| cli.py | Validate, test, run and serve entry points | Lets a person operate the system. |
| app.py | Small API and health interface | Shows what is happening without duplicating engine logic. |

## 7 Configuration contract

### Parsing and validation

Use `yaml.safe_load`. Apply a config-size limit, reject duplicate keys and unknown keys, and validate against typed models. Reject unknown auth, pagination and transform values. No Python expressions, imports, shell commands, custom YAML tags or executable templates are permitted.

Version the schema with `version: 1`. Config IDs must be unique and limited to safe letters, numbers, underscores and hyphens. Use IDs as logical identifiers, never as unrestricted filesystem paths. Show key-specific errors, for example `pagination.offset_param is required for type offset`.

### Example complete config

This is the proposed v1 contract, not evidence of a completed live integration. Verify the remote feed and schema before treating the config as production-ready.

```yaml
version: 1
id: cisa_kev
name: CISA Known Exploited Vulnerabilities
enabled: true

request:
  method: GET
  url: https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json
  params: {}
  headers:
    Accept: application/json
  timeout_seconds: 20

auth:
  type: none

response:
  items_path: vulnerabilities

pagination:
  type: none

schedule:
  enabled: false
  interval_seconds: 900

destination:
  entity: event
  mapping:
    id:
      path: cveID
      required: true
      transform: string
    type:
      constant: known_exploited_vulnerability
    description:
      path: shortDescription
      required: true
      transform: string
    severity:
      constant: unknown
    timestamp:
      path: dateAdded
      required: true
      transform: datetime
      format: "%Y-%m-%d"
      timezone: UTC
      precision: date

limits:
  max_pages: 100
  max_records: 10000
  max_response_bytes: 10485760
  max_run_seconds: 300

retry:
  max_attempts: 4
  base_delay_seconds: 1
  max_backoff_seconds: 30
```

The engine supplies `source` from the config ID and `fetched_at` from its own UTC clock. The mapping must not override those provenance fields. Preserve date-only precision when converting the CISA date to a normalized timestamp; midnight is a representation convention, not a claim that the event occurred at that exact time.

### Authentication variants

```yaml
# API key: resolve NVD_API_KEY from the process environment.
auth:
  type: api_key
  header: apiKey
  secret_env: NVD_API_KEY
```

```yaml
# Bearer token: engine adds Authorization: Bearer <resolved secret>.
auth:
  type: bearer
  secret_env: GITHUB_TOKEN
```

Only `secret_env` names appear in committed config. Resolve secrets immediately before a request. A missing environment value produces `missing_secret`; it must not silently switch to unauthenticated collection. Arbitrary static Authorization, Cookie and API-key values are not accepted as a workaround in `request.headers`.

### Pagination variants

```yaml
# HTTP Link header; follow rel=next until absent.
pagination:
  type: next_link
  header: Link
  relation: next
```

```yaml
# Offset paging; exact parameter names and response paths are configurable.
pagination:
  type: offset
  offset_param: startIndex
  limit_param: resultsPerPage
  start: 0
  page_size: 20
  total_path: totalResults
```

Next-link mode must parse a real Link header, including multiple relations. Resolve relative links against the current URL. Validate every next destination and forbid cross-origin credential forwarding. Do not add the original query parameters a second time when the next link already supplies them. Detect repeated URLs and fail clearly rather than loop forever.

Offset mode starts at the configured offset. Advance by the actual count of items returned, stopping on an empty page or when the configured total is reached. Treat an empty page before a larger advertised total, a non-increasing offset or a repeated page as a pagination failure. Enforce page and record limits. Do not assume a short page always means completion when a total is available. If no total is configured, document and test the supported empty-page stopping behaviour.

If a safety limit stops a collection before the source is exhausted, mark the run incomplete. Do not report a full successful sync or commit its incremental watermark.

## 8 Mapping and common schemas

### Path and transform rules

- Support dotted object paths and numeric array indices, such as `profile.email` and `metrics.cvssMetricV31.0.cvssData.baseSeverity`.
- An empty `items_path` means the response itself must be an array. A missing collection path is a run error, not a successful empty collection.
- Each mapped field uses either `path` or `constant`. Optional fields may specify `default`.
- Whitelist `string`, `integer`, `datetime` and a small lookup transform for enum normalization. Add further transforms only when a selected source needs them.
- Configure lookup tables in YAML. Do not put provider-name branches inside the mapper.
- Missing required fields or failed transforms quarantine the record. Missing optional fields become null or their explicit default.
- Missing means absent or null, not numeric zero or boolean false. Do not collapse valid values with truthiness checks.
- Normalize timezone-aware dates to UTC. Require a configured timezone for naive timestamps. Do not silently use the laptop's timezone.
- No model invents email addresses, severities, login dates or security classifications.

### Common record models

All models include `source` and `fetched_at`. Preserve the original external ID as `id`. Use `(source, entity_type, id)` as the storage identity so two sources sharing the same ID do not overwrite each other.

| Entity | Fields present in the normalized model |
|---|---|
| User | id, name, email, status, source, last_login, fetched_at |
| Device | id, hostname, ip, os, owner, source, last_seen, fetched_at |
| Event/Alert | id, type, severity, timestamp, description, source, fetched_at |

Require a nonempty ID, source and fetched_at for every entity. Require type, description and a timestamp for an Event/Alert. User and Device fields absent from an API may be null; their presence in the schema does not mean a source must expose them. Where timestamps derive from date-only fields, keep optional `timestamp_precision` metadata. Keep normalized severity to `critical`, `high`, `medium`, `low`, `info` or `unknown`. Unknown severity is valid and must not default to high.

Validate each entity after mapping. Preserve record type semantics: a repository issue is `repository_issue`; a CVE is `vulnerability`; a CISA entry is `known_exploited_vulnerability`. These are collected security-relevant records, not proof that an attack occurred.

## 9 HTTP reliability and error semantics

### Request lifecycle

Resolve and validate destination, resolve the secret, build the request, enforce timeout/response limits, send, classify the response and retry if appropriate. Use connection reuse within a run and cleanly close clients. Do not share provider-specific Authorization headers between connections.

### Response handling

| Condition | Behaviour |
|---|---|
| Successful JSON response | Extract the configured collection, map and validate records. |
| Timeout or transient network failure | Retry with bounded exponential backoff. |
| 5xx | Retry within the attempt and run budgets. |
| 429 | Parse Retry-After and wait at least that long before retrying. |
| 401 or 403 | Fail clearly; no blind repeated retries. A provider-specific rate-limit response needs an explicit reviewed extension. |
| Other unsupported 4xx | Fail with a sanitized status and useful category. |
| Unexpected redirect | Reject by default. Never blindly follow to a new host with credentials. |
| Invalid JSON or wrong top-level structure | Fail the run with a parsing/schema reason. |
| One malformed record | Quarantine it and continue the remaining records. |

`max_attempts: 4` means one initial attempt and at most three retries. Default exponential delays are 1, 2 and 4 seconds, with small jitter. These values are engineering defaults, not provider quotas. Inject clock/sleep functions into tests rather than waiting real minutes.

Accept Retry-After as seconds or an HTTP date. If the server-required delay is longer than the remaining run budget, end with a rate-limited/incomplete outcome and retain the next eligible retry time. Do not shorten the server's delay to force the demo to finish. With no valid Retry-After, use bounded backoff and explain the fallback in run history.

Retries must not duplicate saved records. GET-only collection keeps remote side effects out of the initial design.

## 10 Storage and sync state

Use SQLite with parameterized queries. Open connections safely for the thread using them. Enable an appropriate busy timeout and transactions; use WAL if verified on the target setup. Keep write transactions short and never hold a transaction open while waiting for a remote server.

Suggested tables:

| Table | Purpose |
|---|---|
| records | entity_type, source, external_id, normalized JSON, fetched_at and run reference; unique key on source/entity_type/external_id |
| runs | run ID, connection ID, config hash, mode, start/end, outcome, pages, received/accepted/quarantined counts, attempts and sanitized error |
| quarantine | run ID, source, record index or safe ID, field, error category and minimal redacted excerpt |
| sync_state | connection ID, accepted watermark, last success and next eligible retry time |

The normalized payload has the exact User/Device/Event schema even if SQLite uses a common records table. Provide queryable views or filtered API output by entity type.

Upsert an existing record rather than append duplicates. Do not delete existing records merely because a later run did not include them. That needs explicit source deletion semantics outside the initial scope.

Successful earlier pages may remain stored after a later page fails, but the run must expose that it is incomplete. Re-running from the previous committed point must be safe through upsert. Never confuse partial storage with complete collection.

### Incremental sync bonus

Only enable this for sources with a documented modification filter or supported cursor semantics. Keep the previous committed watermark during a run; use a small overlap window where appropriate and deduplicate by stable identity. Advance to a defined safe boundary only after successful completion. Do not advance past quarantined records unless they have a durable recovery path. A failed or limited run never advances the watermark.

## 11 Scheduling and scalable behaviour

Begin with one process, two sync workers and a bounded pending queue of ten jobs. These are configurable defaults, not measured capacity claims. A scheduler periodically checks enabled configs and due times. Manual and scheduled runs share one per-connection lock so the same connection cannot overlap itself.

Use independent per-connection failure state. A slow or rate-limited source must not stop all other connections. When the queue is full, record deferred work or return a clear busy response. Do not create unlimited threads or accumulate unbounded jobs.

On restart, mark abandoned running jobs as interrupted, retain committed state and schedule the next safe attempt. Use a new database connection per store operation or a clearly documented safe equivalent. Shut down workers cleanly.

Process and store one page at a time. Bound response bytes, pages, records and run time. Query health through indexed run summaries instead of loading all normalized records. Paginate the records API and the UI table.

Do not run multiple Uvicorn application workers with an in-memory scheduler, since that would duplicate scheduling. A distributed scheduler/queue is a future deployment decision.

### Benchmark

Benchmark against a controlled local service or mock transport, not public providers' rate limits. Use a repeatable workload such as ten connections with 1,000 records each over multiple pages, then increase load to observe the limit. Report hardware, versions, page size, worker count, throughput, p50/p95 run latency, memory and error counts. Keep benchmark data labelled synthetic. These workload sizes are proposed experiments, not completed results or required public-API volumes.

## 12 Security requirements

### Credentials and data

- Load credentials from process environment variables; `.env.example` contains names and empty placeholders only. If a local `.env` loader is added, exclude `.env` from Git and document that the local file is plaintext protected by filesystem permissions, not encrypted storage.
- Persist no credentials in configs, records, raw response dumps, UI responses or exception traces. Redact Authorization, API-key headers, cookies and known secret values. Disable verbose HTTP logging that may emit sensitive headers.
- Store only necessary normalized data. Quarantine records use minimal redacted excerpts rather than unrestricted raw payloads. If a safe excerpt cannot be guaranteed, store only field/error metadata and a fingerprint.
- API responses and source descriptions are untrusted content. Escape them in HTML. Never render descriptions as executable markup.
- Use placeholders rather than real user data in committed tests. Use unique sentinel credentials to test redaction.

### Request destinations

- Maintain an operator-owned allowlist of permitted HTTPS origins. A connector config cannot grant itself access to a new destination.
- Validate initial requests and pagination URLs. Reject embedded URL credentials, unsupported schemes and unapproved ports/origins. Disable automatic redirects.
- Reject loopback, private, link-local, multicast and other nonpublic resolved destinations in normal mode. Check IPv4 and IPv6 results. DNS changes/rebinding require attention at connection time; use an appropriate transport or deployment egress policy, and document any remaining limitation rather than claiming complete SSRF prevention.
- Local fixture services use an explicit development-only policy restricted to exact loopback destinations/ports. A malicious connector cannot enable that policy. Never allow arbitrary private network access for convenience.
- Do not forward credentials to a next link on another origin. Reject the link and show a policy error.
- Config headers cannot override Host, proxy-forwarding or credential headers controlled by the engine.
- Keep certificate verification enabled.

### Local operator interface

Bind the initial interface to `127.0.0.1`. Do not enable wildcard CORS. Prevent cross-origin requests from triggering runs or config changes. Do not accept arbitrary server-side file paths through the API. Validate config uploads with size limits and safe server-assigned storage paths.

Remote/shared deployment, user accounts, authenticated administration and tenant isolation require a separate hardening milestone before a real customer rollout. This release does not claim production certification or enterprise isolation.

## 13 CLI API and health page

### CLI contract to implement

```text
python -m configbridge.cli validate configs/cisa_kev.yaml
python -m configbridge.cli test configs/cisa_kev.yaml
python -m configbridge.cli run configs/cisa_kev.yaml
python -m configbridge.cli serve --host 127.0.0.1 --port 8000
```

Commands are the intended interface, not claims that these files currently exist. Document environment setup for Windows PowerShell and Command Prompt without printing real tokens. `validate` performs no network calls. `test` makes a bounded request and mapping check but writes no production records or watermark. It reports connectivity/schema compatibility, not proof of full sync permissions or all pages.

### Small API

| Route | Purpose |
|---|---|
| GET /health | Application availability and version, with no secrets |
| GET /connections | Sanitized connection details and health summaries |
| POST /configs/validate | Validate supplied configuration without running it |
| POST /connections | Register a validated configuration, without starting a sync |
| POST /connections/{id}/test | Queue or run a bounded test connection |
| POST /connections/{id}/runs | Queue a sync and return its run ID |
| GET /runs/{id} | Counts, progress, outcome and sanitized errors |
| GET /records | Paginated normalized records filtered by source/entity |
| GET /quarantine | Paginated validation failures with safe excerpts |

Return a busy/conflict response for an overlapping run rather than launching it again. Health status must distinguish idle, running, healthy, degraded, failed and rate_limited as appropriate. Store historical run outcomes separately: success, completed_with_errors, failed, incomplete and interrupted. A completed_with_errors run has quarantined records; it must not display as entirely healthy. A valid empty collection may succeed with zero records.

The page needs a connection list, a records view and a run/quarantine detail view. Show last attempted run and last successful run separately. Include a Run button and Test connection action. Avoid a drag-and-drop workflow builder.

## 14 Real source plan and setup dependencies

Candidate sources come from the organizer's suggested list. Verify current endpoints, free access, response fields, authentication and paging before committing a config.

| Source | Intended data | Login mode | Paging mode | Setup dependency |
|---|---|---|---|---|
| CISA KEV | Known exploited vulnerability entries | none | none | Verify official feed or official cisagov mirror. |
| GitHub REST | Issues or suitable security-related records from an approved repository | bearer | HTTP Link next | User provides a least-privilege token through GITHUB_TOKEN. |
| NVD CVE API | A small filtered collection of vulnerability records | api_key | offset | User obtains NVD_API_KEY and verifies the current API documentation. |

CISA's official mirror is still a CISA source; fetching multiple GitHub repositories does not count as three distinct providers. If a provider is blocked or signup is unavailable, select another real source from the organizer's list and record the substitution. Do not silently substitute a fake provider and declare completion.

NVD permits public access in some modes, but a public unauthenticated run does not demonstrate working API-key authentication. Distinguish the two. If a provider accepts or ignores an optional key on a public endpoint, do not claim that a successful request verified the key's validity. Keep generic auth tests and live-connection evidence separate.

GitHub issue payloads can include pull requests; document a config-expressed filter if collecting issues only. Do not require paid/private security-alert features for the demo. If an endpoint lacks email or login timestamps, preserve null rather than inferring them.

The final three live sources must demonstrate at least two auth methods and two substantive pagination styles across the set. Setup should begin early, while the engine is built with fixtures. Never commit private tokens or ask the assistant to retrieve credentials from unrelated accounts.

## 15 Test plan and completion criteria

Use focused tests of observable behaviour. Do not write tests that merely repeat implementation details. Every acceptance result must be measured and recorded.

### Config and mapping

- Invalid YAML, duplicate keys, unknown options, missing auth references and missing pagination fields give actionable errors before network access.
- Collection path, nested values, array indices, field renaming, defaults, numeric zero and false values work as specified.
- ISO timestamps, configured date-only values, timezone offsets and invalid dates behave predictably.
- User, Device and Event models validate; missing optional data stays null.

### HTTP and pagination

- Check actual API-key/Bearer request headers with sentinel values.
- Multiple Link relations and relative next URLs paginate correctly; repeated/cross-origin links fail safely.
- Offset paging handles totals, empty final pages, repeated pages and unexpected early empty pages.
- 500-then-success and timeout-then-success retry correctly; 401/403 stop; exhausted retries fail.
- 429 respects Retry-After seconds/date and never retries early when its budget is too small.
- Unsafe URL schemes, forbidden destinations and unapproved redirects are rejected.
- Invalid JSON and oversized bodies cannot masquerade as empty success.

### Storage and execution

- Repeated syncs preserve unique records; identical IDs from different sources remain distinct.
- Invalid records do not prevent valid records from being stored.
- Partial failure does not advance a watermark or claim complete success.
- Overlapping runs are prevented; a slow connection does not block every connection.
- A scheduled run fires, a disabled connection stays disabled, and interrupted runs recover safely.
- Captured logs, UI/API outputs and SQLite content contain no sentinel secret values.

### Required live evidence

For each of three real sources record config hash, UTC run time, provider/endpoint category, auth method, paging method, pages traversed, received/accepted/quarantined counts and final outcome. Keep this evidence redacted. Do not include secrets or raw sensitive responses.

### Definition of done

- FR-1 through FR-11 have implementations and passing relevant tests.
- Three distinct real sources have successful documented runs with required auth/pagination diversity.
- A new source using supported capabilities works through config changes alone.
- One end-to-end run is traceable from YAML to database row to health view.
- Failure cases produce honest health states and recover without duplicates.
- Setup, limitations, observed performance and demo steps are documented.
- Prajwal and Mohit can explain the key functions and distinguish their code from library functionality.

## 16 Demonstration plan

Aim for a short live demonstration, with explicit labels for fixture and live modes.

1. Show two existing real connections and the common record view.
2. Add the third real provider's YAML without changing engine code. Start with its config unregistered; credentials may already be supplied securely.
3. Validate and test it, then run a bounded live sync. Show real pages/counters and resulting common-schema records.
4. Open one record and trace its mapped fields back to the config.
5. Re-run and show upsert instead of duplicate accumulation.
6. Use the labelled local failure service to return 429 and 500 responses. Show the shared retry behaviour and recovery.
7. Include a malformed record and show quarantine while valid records continue.
8. Show scheduling, health history and any measured benchmark results.

The key proof is an unchanged engine processing a newly added real source. Avoid spending most of the presentation on a dashboard screenshot. Retain a clearly labelled recorded run if external access fails; report the live failure honestly.

## 17 Explainability checklist for the team

At the end of each milestone, provide a concise explanation and one command to reproduce the result. Keep a short CODE_WALKTHROUGH.md once code exists, with accurate file/function references.

Both teammates should be able to answer:

1. What changes when a new API is added? Its config, provided the engine supports its features.
2. How does the engine know where records are? The configured items_path.
3. How does it fetch the next page? The selected generic pagination strategy.
4. Where is the credential? In an environment variable, resolved by name at request time.
5. What happens to a broken record? It goes to quarantine, with a safe validation reason.
6. Why do retries not create duplicates? Stable storage keys and upsert.
7. Why is a partial run not healthy? Its outcome records that collection did not complete.
8. What keeps a config from accessing arbitrary internal services? Operator destination policy and request validation, with documented deployment limits.
9. What does our code add beyond HTTPX/Pydantic/SQLite? A declarative contract, generic execution, mapping, consistent reliability and observable sync state.
10. What have we actually proven? The tested capability set and the documented real-source runs, not universal API support.

## 18 Optional AI feature

Only after the required release, an AI assistant may propose YAML from API documentation supplied by the user. Keep it separate from execution. Its output must pass the ordinary schema validator and destination policy and require operator review before activation.

Do not give a model secrets, allow it to choose arbitrary network targets or trust undocumented endpoints it invents. Do not automatically fetch arbitrary documentation URLs. Prefer pasted text or uploaded documentation for this optional feature.

The engine must work with AI disabled. AI does not decide that a connection is healthy; real execution results do. Do not train or fine-tune a model for the hackathon requirement.

## 19 Source references and unresolved decisions

### Challenge authority

Organizer document: `PRD_Security_Integration_Requirements_1.docx.pdf`, dated 29 October 2026, authored by Aroop Ghosh, four pages. This local PRD paraphrases its requirements and adds implementation decisions, tests and an order of work.

### Technical references

- HTTPX clients: https://www.python-httpx.org/advanced/clients/
- Pydantic models: https://docs.pydantic.dev/latest/concepts/models/
- GitHub pagination: https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api
- GitHub issue endpoint: https://docs.github.com/en/rest/issues/issues
- CISA official KEV mirror: https://github.com/cisagov/kev-data
- NVD API documentation to verify before implementation: https://nvd.nist.gov/developers/vulnerabilities
- NVD setup/key information to verify: https://nvd.nist.gov/developers/start-here
- OWASP SSRF prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

Provider documentation, dependency compatibility and live access may change. The NVD documentation and CISA website were not fully readable in the planning environment; do not treat live access or final NVD fields as already verified. Verify them on the implementation machine and retain the tested config.

### Decisions still requiring implementation evidence

- Actual available Python/dependency versions and repository state.
- Availability of GITHUB_TOKEN and NVD_API_KEY, supplied securely by the user.
- Exact three live endpoints and their observed current schemas.
- Whether the organizers expect live coverage of all three entity categories, beyond supporting the three common models. Ask this while proceeding with the specified engine; do not fabricate records to fill a category.
- Actual throughput, p95 latency and memory results.

## 20 First message to VS Code Codex

> Read PRD.md and any applicable AGENTS.md. Inspect the repository and current branch. Implement Milestone 0 and Milestone 1 first using the proposed small Python structure, an offline HTTP fixture and SQLite. Verify mapping, quarantine and duplicate prevention, then attempt one bounded real CISA feed run if network access permits. Keep the engine generic and configs declarative. Explain the new code in short, simple terms and tell me the exact commands to run it on Windows. Do not add an LLM or build later milestones before this first complete flow works.
