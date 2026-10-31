# SIEM findings, selected-evidence AI and token usage

## Simple jury explanation

“We collect security data through the same Go engine. Fixed rules identify
findings. PostgreSQL remains the source of truth, and OpenSearch is a searchable
index of approved metadata. Before AI sees anything, the server checks each
search result against the authenticated customer's current database snapshot.
AI receives counts and categories, then explains the evidence. It cannot read
the database, execute queries, change configs or activate connections.”

Example: nine synthetic events include six recent authentication failures,
one recent high event, one old critical event and one future critical event.
The rules find six authentication failures and one high event. AI explains
those two findings, cites e1/e2, and recommends human review. Event descriptions,
emails, IPs, source/customer names, credentials and raw configs are excluded.

## What this first version does

| Rule | Scope |
|---|---|
| `collection_failures` | At least three consecutive failed/incomplete/degraded completed live runs; latest 100 within 24 hours. |
| `mapping_rejections` | Sum of quarantined records across the same sampled runs. |
| `high_severity_events` | Count of source-reported high/critical events in the last 24 hours of event time. |
| `authentication_failures` | At least five events with exact types login_failed, authentication_failure or failed_login in that event-time window. |
| `kev_catalog_entries` | Informational count of recently dated known_exploited_vulnerability events; no deployment-exposure assertion. |

Questions are the fixed topics `connection_health` and `security_findings`.
Arbitrary free-text prompts and query DSL are rejected. Refresh/ask operate on
one live connector. They generate a new snapshot from PostgreSQL, index it, and
filter search by a deployment namespace, tenant, connector, generation and topic.
The provider sees only eN ordinal labels, counts, allowlisted rule/error/severity
values, a 24-hour-window label and the run-sample-cap flag.

Five fixed rules are implemented in Go/SQL. The OpenSearch Security Analytics
plugin's detector/Sigma setup, user/IP correlation, confirmed attack detection,
automatic remediation, broad natural-language investigations and background
continuous indexing are separate future features. Refresh happens on demand.
No speed or capacity gain is claimed without benchmarks.

## Safety and consistency

- Every HTTP operation authenticates a tenant. Findings, snapshots, usage and
  audits also have forced PostgreSQL RLS under a restricted runtime role.
- OpenSearch has a separate hashed index for each namespace/tenant. Indexed
  data is fixed metadata only; connector/tenant names are hashed. Source
  descriptions and original records never enter the index.
- Search returns candidate IDs. PostgreSQL rehydration rejects foreign, stale,
  fabricated, duplicate or missing hits. Index failure or incomplete retrieval
  stops the request; it does not silently send an unfiltered database fallback.
- Snapshot generation changes on refresh. Resolved findings remaining in the
  index have an old generation and cannot be reused. Stable document IDs bound
  retained metadata to the finite rule/category set per connector. Unused old
  indexes need operator retention/deletion policy in production.
- Collection locks serialize snapshot building/indexing with a run. The lock
  is released before the LLM call. Concurrent refresh can invalidate a snapshot;
  that request fails closed and can be retried.
- Event checks use validated event timestamps, not fetched_at. Old records do
  not become fresh findings merely because a source is downloaded again.
  Corrupt stored timestamps fail the query instead of being sent to the model.
- Findings are signals for review. Source severity is not independent incident
  confirmation. Auth counts do not prove a brute-force attack. KEV feed entries
  do not establish that a customer's product/version is affected.
- The Groq adapter validates the evidence again, uses no tools, bounds prompt,
  output and time, rejects extra output fields, and requires valid evidence
  citations. Next checks come from a fixed allowlist. Summaries are untrusted
  explanatory text; they can still be wrong and require human review.
- Separate tenant opt-in and per-request external-AI consent are mandatory.
  Aggregate metadata can still be sensitive. Provider errors are fixed
  categories/statuses; raw provider bodies, prompts and answers are not audited.
- OpenSearch credentials/endpoints are operator settings. Production endpoints
  require certificate-verified HTTPS; redirects are refused. Plain HTTP is
  accepted only in development to literal loopback with no credentials.
- The development `/insights` page uses the existing local console Basic login,
  origin/Host checks, actor-bound expiring CSRF tokens, escaped HTML and CSP.
  The REST routes retain Bearer-only authentication. Production SSO/RBAC is
  outside this local dashboard.

## AI consumption

Both config drafting and SIEM explanations reserve daily call/token budget in
one PostgreSQL transaction before calling a provider. Reservations work across
replicas and persist across restart. Finalization is idempotently fenced.

`CB_AI_DAILY_LIMIT` defaults to 20 calls per tenant/UTC day.
`CB_AI_DAILY_TOKEN_LIMIT` defaults to 400000 tokens per tenant/UTC day, shared
by both operations. A call reserves 40000 tokens conservatively for the bounded
prompt/output contract. Valid provider-reported input/output/total replaces the
reservation, including when output fails validation. Missing usage, errors and
timeouts retain the reservation. This protects the application budget but is
not a guaranteed monetary billing cap or a provider billing reconciliation.

`GET /ai/usage` and `/insights` show the authenticated tenant's current UTC-day
totals and latest 30 tracked requests. Unknown usage is distinct from zero.
Historical calls before migration 006 cannot be reconstructed. Monthly billing,
per-model cost estimates, editable customer-specific plans and a separately
authorized operator view across tenants are future work. Existing credentials
never grant cross-customer dashboard access.

## Local setup: native app, Docker test dependencies

Keep the README's existing private `.env` and local mock TLS certificate. These
containers publish only on localhost and hold synthetic test data. Run them
only if containers with these names are not already running:

```powershell
docker run -d --rm --name cb-siem-search-test --label configbridge.task=siem -p 127.0.0.1:50920:9200 --memory 2g --cpus 2 --cap-drop ALL -e discovery.type=single-node -e DISABLE_INSTALL_DEMO_CONFIG=true -e DISABLE_SECURITY_PLUGIN=true -e 'OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m' opensearchproject/opensearch:3.9.0
docker run -d --rm --name cb-siem-pg-clean --label configbridge.task=siem -p 127.0.0.1:55433:5432 -e POSTGRES_USER=configbridge -e POSTGRES_DB=postgres -e POSTGRES_PASSWORD=local-synthetic-test-only postgres:16-alpine
```

OpenSearch security is disabled only for this isolated localhost synthetic test.
Do not use this setup for customer data or publish its ports publicly. Wait for
PostgreSQL readiness and `http://127.0.0.1:50920` to report its version.

In an API terminal, provision the isolated database:

```powershell
.\scripts\load-env.ps1 -Bootstrap
$env:MIGRATION_DATABASE_URL='postgres://configbridge:local-synthetic-test-only@127.0.0.1:55433/postgres?sslmode=disable'
$env:DATABASE_URL='postgres://configbridge_siem_app:local-runtime-test-only-password@127.0.0.1:55433/postgres?sslmode=disable'
$env:CB_CREATE_RUNTIME_ROLE='1'
go run ./cmd/bootstrap
$env:CB_LISTEN='127.0.0.1:18080'
$env:CB_UI_ENABLED='1'
$env:CB_UI_ORIGIN='http://127.0.0.1:18080'
$env:CB_SIEM_ENABLED_TENANTS='tenant-a'
$env:CB_OPENSEARCH_URL='http://127.0.0.1:50920'
$env:CB_OPENSEARCH_NAMESPACE='siem-native-demo'
$env:CB_OPENSEARCH_USERNAME=''
$env:CB_OPENSEARCH_PASSWORD=''
$env:CB_SMTP_ADDR=''
$env:CB_ALERT_EMAIL_ROUTES=''
go run ./cmd/api
```

Use your actual bootstrap tenant ID if it differs. `GROQ_API_KEY` must already
be in private `.env`; never paste it into chat, committed scripts or screenshots.
The API still needs the local backend's private tenant encryption keyring.

Another terminal starts the TLS fixture:

```powershell
.\scripts\load-env.ps1
$env:MOCK_ADDR='127.0.0.1:18081'
go run ./cmd/mockvendor
```

Then:

```powershell
.\scripts\smoke-siem.ps1
# Explicitly calls Groq once using only synthetic aggregate evidence:
.\scripts\smoke-siem.ps1 -WithAI
```

Open `http://127.0.0.1:18080/insights`. Username is `apikey`; password is your
tenant API key from private `.env`. The smoke prints its unique connector ID.
Refresh its findings, select a topic, tick consent and ask for an explanation.
View the evidence and consumption counters. No config is changed by analysis.

Optional real-browser automation makes one additional synthetic Groq call:

```powershell
npm install --prefix .tools/ui-check --no-audit --no-fund playwright-core
node scripts/smoke-insights.cjs
```

## Tests and verification

```powershell
$env:TEST_DATABASE_URL='postgres://configbridge:local-synthetic-test-only@127.0.0.1:55433/postgres?sslmode=disable'
$env:TEST_OPENSEARCH_URL='http://127.0.0.1:50920'
.\scripts\check.ps1
```

Set both variables to exercise the real Docker-backed path. An absent
TEST_OPENSEARCH_URL skips only the explicit real-search test, so the SIEM push
gate must supply it. Other fault/privacy tests use controlled search/provider
fixtures and real PostgreSQL. They cover event-time windows, source severity,
auth thresholds, collection failure/recovery, tenant isolation, foreign/stale/
duplicate/missing hits, search failures, consent, strict questions, HTML/CSRF,
TLS/redirect/response caps, provider failures, invalid citations/output/usage,
atomic budgets, replay-safe finalization, unknown usage and restart persistence.

Verified on the local machine across 2026-10-31/2026-11-01: the fetched/merged
baseline passed first; the expanded full race/vet/formatting/native-build gate
passed against Docker PostgreSQL and OpenSearch 3.9.0. The compiled synthetic
flow produced 6 auth failures and 1 high event. The first live Groq call reported
499 input + 191 output = 690 tokens, recorded once. A second browser call brought
the observed total to 1353 tokens. Edge refreshed findings, rejected missing
consent, displayed evidence and usage, and fit a 390px mobile viewport. Screenshots
and safe test results remain ignored under data/.

The final full gate also passed after the metered-draft regression and dashboard
layout fixes. All six static Linux/amd64 command builds passed. Six SIEM logs
contained none of the configured provider/API/SMTP/database passwords. No Dockerfile
or application Compose service was changed for this work.

This evidence is synthetic-source/local integration testing, not real customer
threat-detection effectiveness, production OpenSearch security, or a performance
benchmark. Mohit retains application containerization and Bedrock work.

## Files in simple terms

| File | Job |
|---|---|
| `internal/insights/types.go` | Defines the tiny set of facts AI is allowed to receive and validates answers. |
| `internal/insights/search.go` | Writes fixed metadata to OpenSearch and retrieves scoped candidate IDs. |
| `internal/store/siem.go` | Computes rules from PostgreSQL and rechecks retrieved IDs. |
| `006_siem.sql` | Adds tenant-protected snapshots, findings and AI token records. |
| `internal/store/ai_tokens.go` | Atomically reserves budgets and records actual or unknown usage. |
| `internal/aidraft/groq.go` | Calls Groq, captures usage and validates cited SIEM explanations. |
| `internal/api/siem.go` | Authenticated refresh/findings/ask/usage handlers and provider interface. |
| `internal/api/insights_page.go`, `insights.html`, `insights.css` | Local findings and token dashboard. |
| `internal/app/siem.go` | Reads operator opt-in, search settings and provider configuration. |
| `internal/api/draft.go`, `internal/app/ai.go` | Add token accounting to existing public-source drafting. |
| `cmd/api/main.go`, `internal/api/api.go`, `onboarding.go` | Wire startup, routes and protected local console access. |
| `internal/mockvendor/mockvendor.go`, `configs/mock_security_events.json` | Synthetic security data and its declarative config. |
| `scripts/smoke-siem.ps1`, `smoke-insights.cjs` | Test the compiled flow and actual browser. |
| `tests/siem_test.go`, `ai_metering_test.go` | Combined database/search/API/privacy and draft-usage tests. |
| `internal/insights/*_test.go`, `internal/aidraft/siem_test.go` | Evidence, transport and provider failure tests. |
| `internal/store/ai_tokens_test.go`, `internal/app/siem_test.go`, `internal/api/siem_access_test.go` | Quotas, persistence, configuration and authorization tests. |
| `.env.example`, `scripts/load-env.ps1` | Document and load settings; private values stay uncommitted. |

## Bedrock handoff and remaining work

Mohit implements `api.Explainer` with Name, Model and Explain. The Explain method
accepts only `insights.Evidence` and returns `insights.Answer`, `insights.Usage`
and an error. Report known provider usage even when output validation fails;
unknown usage must stay unknown. Do not pass raw records/configs or silently
fall back between providers. Preserve shared budgets, tenant opt-in and consent.

The remaining real free-tier source/live evidence is still Mohit's deferred work.
The requested environment-variable/vault verification also remains separate;
encrypted PostgreSQL credentials already satisfy the original FR-6 option.
