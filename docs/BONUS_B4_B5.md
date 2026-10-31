# B-4 email alerts and B-5 onboarding

## Explain it to the jury

**B-4:** “Suppose our GitHub connection fails three times. We store an alert and
email the customer's configured address. Further failures in the same outage
do not create more alerts. If email delivery fails, we retry it. When GitHub
recovers, pending alerts stop.”

**B-5:** “For another supported vendor, fill a form with its HTTPS endpoint,
authentication reference, pagination and field mapping. Our Go server generates
the config. Download it, save it as a draft and test a sample. Turning it on is
a separate, deliberate action.”

The local demo uses an invented vendor. Neither feature sends data to AI.
The existing Groq draft endpoint is a separate, explicit-consent feature.

## Start the local demo

Use the README's existing private `.env`, local PostgreSQL and TLS certificate.
Run bootstrap again to apply migration 005 before starting the API:

```powershell
.\scripts\load-env.ps1 -Bootstrap
go run ./cmd/bootstrap
```

Terminal 1, synthetic TLS vendor:

```powershell
.\scripts\load-env.ps1
go run ./cmd/mockvendor
```

Terminal 2, synthetic mailbox (no email leaves the computer):

```powershell
go run ./cmd/mailcapture
```

Terminal 3, API with a fake local-only email destination:

```powershell
.\scripts\load-env.ps1
$env:CB_UI_ENABLED = '1'
$env:CB_UI_ORIGIN = 'http://127.0.0.1:8080'
$env:CB_SMTP_ADDR = '127.0.0.1:1025'
$env:CB_SMTP_FROM = 'alerts@example.invalid'
$env:CB_SMTP_USERNAME = ''
$env:CB_SMTP_PASSWORD = ''
$env:CB_SMTP_TLS_MODE = 'plain'
$env:CB_ALERT_EMAIL_ROUTES = '{"tenant-a":"jury@example.invalid"}'
$env:CB_AI_ENABLED_TENANTS = ''
go run ./cmd/api
```

These overrides affect this terminal only. Use the actual bootstrap tenant ID
if yours differs. Restart the API after changing operator routes. The mailbox
is a bounded, unauthenticated loopback test utility; use only synthetic messages.
The native demonstration is verified; Docker startup remains unverified.

## Show B-4

In another terminal:

```powershell
.\scripts\smoke-notifications.ps1
```

It creates a unique synthetic connector, fails it twice without an alert, fails
a third time and waits for one captured email. A fourth failure must not send a
second email. It then recovers the connection and disables its demo alerts.
Open `http://127.0.0.1:8025` to show the captured message. Inspect delivery metadata
through authenticated `GET /alerts?connector=<demo ID>`.

The connector option is:

```json
"notifications": {
  "enabled": true,
  "failure_threshold": 3,
  "cooldown_seconds": 3600
}
```

Recipients belong to operator settings, never connector JSON. Threshold is
1–100; cooldown is 60–604800 seconds. A clean success resets the failure streak.
Failed, incomplete and mapping-degraded live runs count; previews and interrupted
runs do not. Cooldown survives recovery and protects against flapping.

The run outcome and alert insertion commit together. The worker claims durable
outbox rows under a connector lock and a fenced lease. It retries delivery up to
five attempts with backoff; recovery or opting out cancels pending work. A sent
email cannot be recalled. Email is at least once: a lost connection after SMTP
acceptance can cause a retry. Stable Message-IDs help identify duplicates but
cannot guarantee exactly-once delivery.

Messages contain tenant/connector/run IDs, failure count and a fixed error
category. They contain no credentials, vendor response bodies or record values.
Production SMTP uses certificate-verified STARTTLS or implicit TLS, TLS 1.2+,
and a 15-second total deadline. Plain SMTP is allowed only in development to a
literal loopback address with no authentication credentials. Real external
mailbox delivery has not been tested; no real recipient was contacted.

## Show B-5

1. Open `http://127.0.0.1:8080/onboarding`.
2. Browser login: username `apikey`; password is your tenant key from private
   `.env`. Keep it out of screenshots and shared exports.
3. Choose **Users**. Enter ID `jury_users`, a display name and endpoint
   `https://127.0.0.1:8081/users`. Set HTTPS port `8081`; authentication `none`.
4. Choose page pagination. Expand its options; page parameter `page`, size
   parameter `per_page`, page size `10`. Map `id` to `id` and `name` to
   `profile.name`. Leave scheduling off. Email is optional when a route is ready.
5. **Generate config**, inspect JSON and **Download JSON**.
6. **Save as draft**, then **Test saved draft**.

Expected: one sampled page, 10 accepted users, zero mapping errors. The draft
stays inactive. Preview writes no production records, run history, quarantine,
incremental progress or alerts. Activation remains an authenticated API action.

User, Device and Event forms share the ordinary validator. Authentication can
reference an existing credential from the current tenant's dropdown; credential
values are added separately through the write-only secrets API. The form lists
up to 500 stored credential names. More specialized configs can use the JSON API.

The console is development-only and accepts only its configured localhost
origin/Host. POSTs also need an expiring token bound to the authenticated tenant
and key identity. HTML output is escaped; CSP blocks scripts and framing. No
cookies, localStorage or key-in-page fields are used. Same-origin referrer policy
keeps genuine form Origin headers usable while suppressing cross-origin
referrers. REST endpoints retain Bearer-only authentication and browser-origin
rejection. Local HTTP Basic login is not production SSO or role-based approval.

## Verification

Before these changes, the fetched Member A/member-b baseline passed the full
local gate in an isolated worktree. The final feature gate uses real PostgreSQL,
`go vet`, all tests with `-race`, and all six native builds:

```powershell
$env:TEST_DATABASE_URL = '<disposable PostgreSQL admin URL>'
.\scripts\check.ps1
```

Tests cover thresholds, deduplication, retries, exhaustion, recovery, cooldown,
stale leases, opt-out, mapping degradation, missing routes, tenant isolation,
SMTP privacy, certificate checks, STARTTLS downgrade refusal and cancellation.
Form tests cover all schemas, strict input validation, HTML escaping, CSRF,
origin checks, cross-tenant access, credential references, inactive drafts and
preview side effects. The regression suite also exercises existing incremental,
auth, egress, scheduling, secrets, upsert and quarantine behavior.

Optional actual-browser check on Windows, with API/vendor/mailbox running using
the synthetic settings above (Node and Edge are test tools only):

```powershell
npm install --prefix .tools/ui-check --no-audit --no-fund playwright-core
node scripts/smoke-onboarding.cjs
```

It generates/downloads/saves/tests a config in Edge, verifies no production
records/history and no activation, then checks mobile overflow. Screenshots and
safe result files stay in ignored `data/`. The real browser check caught a
referrer-policy issue missed by HTTP-only tests; that issue is fixed.

Verified locally on 2026-10-31: the complete PostgreSQL/race/vet/formatting gate,
all six Windows builds, all six Linux/amd64 static builds and Compose config
validation passed. Compiled full-sync and email demos passed. The real Edge
flow generated/downloaded/saved/tested a draft, accepted 10 sample users, wrote
no production data/history/alerts, stayed inactive and fit a 390-pixel viewport.
Nine local test logs contained none of the configured API/provider/SMTP/database
passwords. These results do not establish external mailbox delivery or production
capacity, and actual Docker startup was not exercised.

## Files in simple terms

| File | Job |
|---|---|
| `pkg/config/config.go` | Defines and validates alert settings. |
| `005_notifications.sql` | Adds tenant-protected alert counters and delivery queue. |
| `internal/store/alerts.go` | Counts failures, queues alerts and tracks delivery/recovery. |
| `internal/store/store.go` | Applies the migration and commits alerts with run outcomes. |
| `internal/notify/worker.go` | Picks queued alerts and retries email delivery. |
| `internal/notify/smtp.go` | Sends bounded, metadata-only email over verified TLS. |
| `internal/app/notifications.go` | Reads private operator relay and tenant-route settings. |
| `internal/api/alerts.go` | Lets a tenant inspect its own alert history. |
| `internal/onboarding/console.go` | Restricts console origins and signs form tokens. |
| `internal/onboarding/form.go` | Converts form fields into a validated Go config. |
| `internal/onboarding/page.go` | Embeds and renders the page. |
| `internal/onboarding/page.html` | Form, JSON review and sample-test screens. |
| `internal/onboarding/style.css` | Desktop and phone layouts. |
| `internal/api/onboarding.go` | Generates, downloads, saves and tests drafts. |
| `internal/api/api.go` | Routes requests and checks authentication/origins. |
| `internal/app/onboarding.go` | Enables the console only in development. |
| `cmd/api/main.go` | Starts the console routes and background email worker. |
| `internal/mailcapture/server.go` | Stores synthetic test emails locally. |
| `cmd/mailcapture/main.go` | Starts the loopback-only test mailbox. |
| `.env.example`, `scripts/load-env.ps1` | Document/load settings without committing private values. |
| `docker-compose.yml` | Passes the optional settings to the API container. |
| `scripts/smoke-notifications.ps1` | Runs the compiled local email demo. |
| `scripts/smoke-onboarding.cjs` | Clicks through the real browser demo automatically. |
| `tests/notifications_test.go`, `tests/onboarding_test.go` | Test the combined API, TLS vendor and real database. |
| `internal/notify/smtp_test.go` | Tests SMTP TLS, timeouts, downgrade refusal and privacy. |
| `internal/onboarding/form_test.go` | Tests mapping, form validation, tokens and escaped HTML. |
| `internal/app/bonus_test.go`, `internal/api/access_test.go` | Test configuration defaults and route authorization. |

Reminder: Mohit's remaining real free-tier API integration and its live
authentication/pagination evidence are still pending, as requested.
