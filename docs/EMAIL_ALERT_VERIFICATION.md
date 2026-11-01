# B-4 dashboard and real email verification

Verified 2026-11-01 after fast-forwarding `member-b` to `origin/main` at
`40696ee`. Main contained the merge of our preceding work; no conflicting
source changes were present.

## What changed

- **Email alerts** in the main sidebar shows this tenant's setup capability,
  live source settings and paginated delivery history with a source filter.
- Source editing now exposes failure threshold, cooldown and enable/disable.
  Saving a draft does not change the displayed live settings; activation does.
- `GET /notifications/status` reports configured/disabled and local-capture/SMTP
  mode. It returns no SMTP credentials, recipients or other tenant routes.
- Explicit `CB_ALERT_USE_ACCOUNT_EMAIL=1` selects the oldest active admin within
  the affected tenant under PostgreSQL RLS. An operator's private route overrides
  this default. Disabled users/viewers are excluded; recipients are resolved at
  delivery time. No recipient address can be supplied in a connector config.
- A setup refusal now appears as a visible pipeline error instead of assuming
  every validation response contains an `errors` array.
- Older email-page refresh responses cannot overwrite a newer page load.

## Checks performed

| Check | Result |
|---|---|
| Independently test merged baseline | SMTP, notification, authenticated route and YAML flow tests passed with race detection and real PostgreSQL. |
| Full release check | `go vet ./...`, `go test -race -count=1 -timeout=180s ./...`, `go build ./cmd/...` passed in Docker with PostgreSQL and OpenSearch. Live opt-in vendor/provider tests are separate. |
| Account email selection | Missing admins, viewer exclusion, disabled-admin exclusion, two tenants using the same connector ID, operator route precedence and captured SMTP delivery passed. |
| Live versus draft settings | A disabled draft left enabled live alerts unchanged; activation changed the reported live settings. |
| Browser flow | Edited source settings, saved/activated, ignored preview, delivered one captured alert after three live failures, suppressed the fourth failure's duplicate, recovered and opted out. |
| Browser isolation | The second customer could not see the first customer's source or email history; foreign connector filtering returned 404. No JavaScript errors. |
| Real Gmail | TLS certificate verification, STARTTLS and SMTP authentication passed. Three synthetic live failures queued one alert; Gmail accepted it on the first delivery attempt. The user confirmed inbox receipt. |
| Cleanup | The real-send proof source recovered and its notifications were disabled. Old browser-proof notifications were disabled; records and delivery history were retained. |

Private logs, screenshots, settings and runtime proof identifiers remain in
ignored `data/`. SMTP secrets remain in private environment files and were not
committed. Evidence includes `email-release-gate.log`, `email-browser-result.json`
and `gmail-alert-result.json`. Inbox confirmation came from the user after the
SMTP proof; it is not inferred from an SMTP response.

## Show it

1. Open `/ui/#/email-alerts` in the locally running dashboard.
2. Check the setup card. “SMTP configured” permits an attempt; it is not a delivery guarantee.
3. Find the synthetic Gmail proof source in **Delivery history**, or select it in
   the source filter. Its historical alert should show **sent**, three failures
   and one delivery attempt.
4. Open the authorized receiving inbox to show the real message.
5. For another source, **Edit source → Failure email alerts (B-4)**, enable it,
   then **Save** and **Activate**. Deliberately trigger failures only on a test
   source; enabling notifications does not itself send an email.

The default recipient is one account admin, not every IAM user and not the
vendor's support address. Existing account email addresses are not independently
verified by ConfigBridge. Root-key-only accounts need a private route or an admin
user. Delivery is at least once with up to five attempts, so ambiguous SMTP
acknowledgements can produce duplicates. Recovery cancels pending mail but cannot
recall accepted mail. No collection records, vendor credentials or raw vendor
responses are sent. Exact KEV matches remain dashboard-only.

## Files in simple terms

| File | Purpose |
|---|---|
| `internal/api/alerts.go` | Tells the dashboard if this customer's email setup is ready and lists delivery history. |
| `internal/app/notifications.go` | Reads private SMTP settings and chooses explicit routes or account email mode. |
| `internal/store/iam.go` | Finds an active admin email inside the correct customer account. |
| `internal/notify/worker.go` | Resolves the recipient and delivers queued alerts using existing retries and locks. |
| `internal/store/store.go` | Includes live notification settings in source summaries. |
| `internal/ui/static/app.js` | Adds the email page, source controls and clear setup errors. |
| `cmd/api/main.go` | Connects the notification worker and readiness check to the API. |
| `.env.example`, `docker-compose.yml` | Document and pass the opt-in account-email setting. |
| `tests/notifications_test.go`, `internal/app/bonus_test.go`, `internal/api/access_test.go` | Check routing, privacy, validation, activation and authentication. |
| `scripts/check-email-alerts.cjs` | Tests the local browser/capture flow and refuses external SMTP. |
