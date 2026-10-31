# AI usage and request logs

## Explain it to the jury

"Each AI request gets a usage receipt in PostgreSQL. We total those receipts
per customer, day and model. A customer sees only its own receipts; a separately
authorised platform operator can compare accounts. We store usage metadata,
not the customer's prompts, answers or API keys."

| File | Simple explanation |
|---|---|
| `internal/store/ai_tokens.go` | Existing ledger: reserves budget and saves actual provider token counts. |
| `internal/store/migrations/013_ai_reports.sql` | Adds the bounded queries that calculate dashboard totals. |
| `internal/store/ai_reports.go` | Reads those reports into Go structures. |
| `internal/api/ai_reports.go` | Checks permissions and filters before returning a report. |
| `internal/ui/static/ai-usage.js` | Draws the customer and operator dashboards. |
| `tests/ai_reports_test.go` | Proves totals, tenant isolation, dates and operator access work. |

## What the customer sees

Open `/ui/#/ai-usage` after normal account sign-in. It shows that account's AI
requests, provider-reported input/output/total tokens, daily chart, model and
operation breakdown, unsuccessful requests and request history. Choose up to 90
UTC days. Request logs have 50 rows per UI page (API limit: 100).

The backend reads the existing PostgreSQL `ai_requests` ledger. Opening the
dashboard does not call a model or consume AI tokens. The ledger survives app
restarts. Draft generation and SIEM explanations share it; repair calls are
included when the provider supplies usage. An application request may contain
multiple provider attempts, so these request counts are not provider RPM/RPD.
Receipts start when budget is reserved; preflight validation or budget denials
before that point are not listed as metered requests. Duration runs from that
reservation until finalization, rather than measuring all preflight work.

## What the platform operator sees

Open `/ui/#/platform-ai`, or follow **Platform AI usage** on the sign-in page.
Enter `CB_OPERATOR_TOKEN` from the private server `.env`. This is a separate
platform credential, not a vendor API key, customer access key or tenant IAM role.
It must be at least 32 characters. Restart the API after changing server settings.
The existing Compose file already passes this setting to the API.

The operator can compare customer account ids, click a customer for its report,
or filter by account id. The overview lists the top 200 accounts by reported
tokens; account filtering also works for customers outside that list. It is
read-only: it does not edit tenant budgets, users, credentials or source records.
Use **Lock platform view** when finished. The browser holds this credential only
in page memory and clears it on lock/navigation; reloading requires it again.
No operator credential is stored in browser storage, URLs or cookies.

## Unknown is not free

- Reported tokens: usage actually returned by a provider, including unsuccessful
  requests where usage was returned.
- Held tokens: the conservative reservation for requests with no trustworthy
  total yet. This is a budget hold, not a measurement or provider charge.
- Finished without usage: the request ended, but provider usage is missing.
- Not finalized: no finalization was recorded. A crash can leave a reservation
  pending; the dashboard cannot prove such a request is still executing.
- Unsuccessful: a finalized outcome other than `drafted` or `explained`.

The system retains unknown reservations rather than treating missing usage as
zero. Daily budgeting resets at UTC midnight; historical report holds describe
that day's ledger, not a current-day balance. This view does not estimate money
or replace provider invoices. Rates, cached-token pricing and model prices would
need a separately maintained price catalogue before displaying currency.

## Security and limits

Customer `GET /ai/consumption` uses the authenticated tenant scope and PostgreSQL
RLS. It rejects a supplied customer/tenant filter. Ordinary customer keys and
sessions cannot use `GET /operator/ai/consumption`; that route separately checks
the platform credential, same-origin browser policy and rate limits.

Migration 13 adds a bounded reporting function and a narrow security-definer
wrapper for the trusted API's operator path. Its search path is fixed; table
names are schema-qualified; execution is revoked from PUBLIC and granted to
the runtime service role. The wrapper can expose AI ledger metadata across
tenants; it cannot read general customer records or secrets. Runtime database
credentials belong only to the trusted backend, never to customers.

Logs expose request id, operation, provider/model, outcome, timestamps, duration,
and token fields. They exclude prompt/answer bodies, raw records, credentials,
user emails and source details. Responses are `no-store`; UI values use text
nodes. Date windows, page sizes and offsets are bounded, SQL has a five-second
statement timeout, and a creation-time index supports operator date scans.
This is not a fleet-scale billing warehouse; daily rollups and cursor pagination
would be sensible before serving millions of ledger rows per window.

## Verification

- Full `scripts/check.ps1` passed with real Docker PostgreSQL and OpenSearch:
  formatting, vet, race detection, full tests and every native command build.
- Two-tenant HTTP/DB tests cover UTC start/end boundaries, known and unknown
  usage, pending/failure counts, pagination, malformed filters, foreign-tenant
  rejection, operator authentication, direct RLS behavior and reopening the pool.
- Existing actual draft/retry metering test now verifies the new report matches
  successful and rejected model outputs.
- Rebuilt the existing Docker API/bootstrap images and ran the console in Edge
  against Docker API/PostgreSQL with synthetic ledger data. Checked customer
  sign-in, cross-customer comparison, drilldown, pagination, invalid-date feedback,
  escaped model text, locking/reload, token storage and a second customer's view.

No live provider comparison was performed for this feature; it needs no real AI
key. The Docker dashboard demonstration contains explicitly synthetic usage,
not actual customer charges. Evidence is local under `data/ai-dashboard-*`.
