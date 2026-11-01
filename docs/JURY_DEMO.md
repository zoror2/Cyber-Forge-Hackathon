# Complete local demo guide

This guide covers the engine, FR-1 through FR-11, B-1 through B-5, IAM,
tenant separation, KEV correlation, SIEM questions, AI repair and AI usage.
Use the results in `data/jury-demo-checks.json`, `data/jury-browser-checks.json`
and the final verification note to distinguish tested paths from external dependencies.

## 1. Open the prepared dashboard

- URL: **http://127.0.0.1:55080/ui/**
- Account: `jury-demo`
- Email: `jury@demo.test`
- Password: `Jury-demo-only-2026!`
- Second isolated account: `jury-other`, with the same demo email/password.

These are synthetic, localhost-only demonstration accounts. Do not use these
credentials for a public deployment. The existing local Docker API, PostgreSQL,
TLS vendor fixture and OpenSearch must be running. Mohit handles AWS separately.

The saved local settings are `data/docker-app-proof/settings.env`; they contain
private credentials, so do not open that file during screen sharing. The demo's
own API throttling is disabled through the existing development-only switch to
allow rapid rehearsal. Vendor retries and rate-limit handling remain active.

To prepare/rehearse again from the repository root:

```powershell
node scripts/prepare-jury-demo.cjs
```

This creates synthetic sources and accounts, runs checks and writes sanitized
sample configs under `data/jury-demo-configs`. It intentionally restores
`demo_repair` to a broken conversion so the repair button can be demonstrated.
It does not delete customer data. Rehearsals create a fresh incremental source
so an old checkpoint cannot invalidate the starting counts.

## 2. Suggested 10–15 minute jury order

| Order | Page/action | What to explain |
|---|---|---|
| 1 | Overview | One place shows source health, accepted/rejected counts and last results. Some red sources are intentional failure tests. |
| 2 | Sources → `demo_users` → Test, then Run | A config controls fetching, pagination and mapping. Preview samples without storing; a real run stores records. |
| 3 | OCSF records → Users → source `demo_users` | 25 users collected across 3 pages. Running again keeps 25 unique rows. |
| 4 | Add source → Paste a config | Show the full validate → preview → activate → collect flow without depending on AI. |
| 5 | Quarantine → `demo_malformed` | Two valid rows were accepted and two invalid rows were isolated with reasons. |
| 6 | Quarantine → `demo_repair` → Fix config with AI | AI selects a verified conversion, then preview and a real rerun verify it. |
| 7 | KEV alerts | A real CISA catalog is compared with synthetic asset findings by exact CVE. Two matches need review. |
| 8 | Insights → `demo_vulnerabilities` → security topic | Type a question; approved evidence is retrieved and checked before the model answers. |
| 9 | AI usage | Show this customer's requests, provider/model, measured tokens and unknown reservations. |
| 10 | Users & keys; then second customer | Explain roles, two access keys per user and immediate revocation; demonstrate separate data. |
| 11 | Runs; optional failure/incremental demos | Show exact config revisions, attempts, limits and change-only collection. |

## 3. Collect, map and prevent duplicates — FR-2, FR-3, FR-5, FR-11

1. Open **Sources**, find `demo_users`, press **Test**.
2. Test returns a bounded first page: **10 accepted**. It does not insert records,
   advance a checkpoint or create a live collection history entry.
3. Press **Run**. Expect **25 accepted, 3 pages, success**.
4. Open **OCSF records**, choose **Users**, select `demo_users`.
5. Run it again and refresh the records: still **25 unique users**.
6. Click a row to inspect the common OCSF JSON. Names came from `profile.name`;
   dates became OCSF timestamps; source and tenant metadata came from the server.

Say: “Every vendor may return different JSON. The config tells our Go mapper
where fields are, and PostgreSQL updates the same record instead of duplicating it.”

## 4. Add a source without AI — B-2, B-3, B-5

1. **Add source → Paste a config**.
2. Paste `data/jury-demo-configs/demo_users.json`; change `id` to `jury_new_users`
   and `name` to `Jury-created synthetic users` so this is a new source.
3. Press **Check config**, inspect the returned settings, then **Connect**.
4. The wizard saves, validates, previews, activates and performs the first fetch.
5. Press **See the data** and show the collected records.
6. For a negative example, change the URL to `http://...` or add an unknown key
   and check again. Validation must reject it before collection.

Say: “AI is optional. A correct supported config works through the deterministic engine.”

## 5. AI template generation and assistance

1. Open **Add source → Set up with AI**.
2. Enter the product. For GitHub, explicitly select the intended dataset/scope
   (for example public repository contributors); do not select enterprise data
   when collecting a public repository.
3. Supply public API documentation or an OpenAPI specification when name-only
   discovery cannot establish an exact contract.
4. Inspect sources/evidence, the endpoint, authentication, response fields and
   required local inputs before connecting.
5. Fill credentials and customer-specific path/address inputs locally.
6. Check and preview before activation. A usable model draft is not proof that
   the account has vendor access or that a particular token has sufficient scope.

Reviewed-profile and documentation/spec behavior are covered by automated tests.
A live browser check also passed the GitHub public-contributors template, official
sources, required owner/repository inputs and blocked Connect before credentials.
The small live checks verify questions and repair as well; they do **not** certify
every vendor's name-only live drafting. Hosting quota, vendor docs availability
and external search can still fail. Show the manual flow if that happens.

## 6. Bad records and repair — FR-9

### Preserve valid records

Open **Quarantine**, select `demo_malformed`: expect **2 invalid records** with
field/reason information. **OCSF records → Users → demo_malformed** contains the
**2 valid records**. Raw rejected payloads are not retained.

### Repair and rerun

1. Select `demo_repair`. Its synthetic config incorrectly converts user names
   to integers; the prepared run quarantines **25 rows**.
2. Tick repair consent, then **Fix config with AI**.
3. The server tests a bounded sample locally and presents only verified
   conversion choices/counts to the model.
4. It validates the selected config, saves a revision and previews it.
5. Only a successful preview with accepted rows and no quarantined sample rows
   allows activation and a rerun.
6. Expect **repaired and rerun**, **25 accepted, 0 quarantined** in the new run.
7. Inspect **Runs** to compare old and new config revisions.

Historical quarantine rows remain as audit evidence. Inspect the new run's counts
to judge whether the repair succeeded. Sample success cannot guarantee later pages
or future data. Missing paths, ambiguous mappings, invalid source values, multiple
simultaneous errors and incremental-source repairs require documented/manual review.
Automatic repair cannot change URLs, credentials, field paths, record identities,
required flags or filters. A concurrent config change stops stale activation/run.

## 7. KEV alerts: what was actually detected

1. Open **Sources** and show `cisa_kev`: it collects the real public CISA catalog
   from CISA's official GitHub mirror.
2. Show `demo_vulnerabilities`: its **three asset findings are synthetic**.
3. Open **KEV alerts**. Expect two matches:
   - `CVE-2021-44228`
   - `CVE-2024-3400`
4. The synthetic `CVE-2099-99999` is absent from the alert list.
5. Show each match's source, record, run reference and fetch time.

Say: “The backend joins CVE IDs from this customer's collected vulnerability
findings with this customer's trusted CISA catalog. A vendor/company-name match
alone does not trigger these alerts. AI explains the verified result.”

These matches do not prove active compromise or that an affected version is still
installed. Review asset versions, source freshness and remediation status. The
dashboard checks retained records when opened/refreshed; background email delivery
is not part of this KEV alert flow. Other customers cannot reuse this catalog implicitly.

## 8. SIEM questions and privacy

1. Open **Insights**, source `demo_security`.
2. **Refresh findings**: expect six failed-login events and one recent high-severity
   event. Old/future high events are excluded by event time.
3. Select the security evidence topic, type:
   `What should I investigate about these failed logins?`
4. Tick consent and press **Explain**. Inspect citations and next checks.
5. For KEV, source `demo_vulnerabilities`, security topic, ask:
   `What does the KEV match mean, and what should I verify next?`
6. An unanswered question must remain uncertain if the approved facts cannot answer it.

PostgreSQL holds records. OpenSearch holds approved finding metadata and returns
candidate IDs. The backend rechecks tenant, source and snapshot before sending
the model a bounded evidence set. The model receives the consented question,
counts/categories and matched public CVE IDs, never SQL access or a full database dump.
Do not put sensitive details in the question. Basic credential/email/URL patterns
are rejected; this is not a universal detector for all personal or confidential data.

The events are synthetic because no real sensor is installed. OpenSearch itself
is running and tested. This is a small rule-based SIEM assistance flow, not a
complete detector/Sigma deployment or a universal security investigation system.

## 9. Tokens, customer consumption and operator view

1. Open **AI usage** after a question or repair.
2. Show total requests, measured input/output tokens, model and operation history.
3. Explain that unknown provider usage keeps a reservation; it is not a measured bill.
4. Apply date filters and page through requests if enough exist.
5. A customer's two API access keys contribute to the same customer budget.
6. The separate platform page is `http://127.0.0.1:55080/ui/#/platform-ai`.
   It requires `CB_OPERATOR_TOKEN`, not a customer key. Retrieve it privately;
   do not display the settings file on the shared screen.
7. Platform operators can compare/drill into customers. Lock the view afterward.

API keys from the same hosted-AI account often share provider quotas. Creating a
new key does not establish that an account's quota has reset. If a provider returns
429, show the clear failure and token ledger; the collection engine remains usable.

## 10. IAM, multiple keys, credentials and isolation — FR-1, FR-6

- **Users & keys:** show admin/editor/operator/viewer roles. Users inherit fixed
  allowed actions; viewer cannot edit/run/repair. A user may have two access keys.
- Access-key values are shown once; the database stores hashes. Revoking a key or
  disabling its owner takes effect immediately. Tests cover both customer keys
  and several simultaneous vendor tokens without mixing their credentials.
- **Secrets:** `demo_vendor_token_port` is bound to `mockvendor:8081`. The value
  is write-only and encrypted locally. Show metadata only, then run `demo_secure`.
- Sign out and sign into **jury-other**. Sources/records are empty, KEV says the
  catalog is missing, and usage belongs only to that account.
- Sign back into **jury-demo**. Both API permission checks and PostgreSQL RLS
  enforce separation; changing a tenant header cannot select another customer.

Local encryption uses keys from private environment configuration. The AWS vault
adapter has mocked tests; live AWS validation/deployment is Mohit's remaining work.

## 11. Retry, rate limits, timeouts and resource boundaries — FR-7, FR-8, FR-10

Open **Runs** and filter these synthetic sources:

| Source | Expected result |
|---|---|
| `demo_retry` | Initial 5xx responses, then success after 3 attempts during preparation. |
| `demo_rate_limit` | One 429, bounded Retry-After wait, then success after 2 attempts during preparation. |
| `demo_timeout` | Failed run with `timeout`. |
| `demo_redirect` | Redirect refused with `destination_denied`. |
| `demo_size` | Oversized response refused with `response_too_large`. |

The fixture remembers retry scenarios. A later manual rerun may succeed immediately;
use a new `request.params.scenario_id` or prepare again to repeat the initial failures.
Overview deliberately shows these failed sources as needing attention. Counts and
errors are real run results, not proof that the whole demo is broken.

The full tests also exercise pagination loops, off-host links, malformed responses,
missing/invalid credentials, response limits, record/page/time bounds, overlapping
jobs, tenant fairness, cancellation/recovery and incomplete runs.

## 12. Scheduling and incremental sync — FR-4, B-1

### Schedule

Edit a synthetic source using **Manual edit**. Turn scheduling on, set a short
interval such as 10 seconds, then save/validate/preview/activate. Refresh **Runs**
to see automatic runs. Turn the schedule off and activate that revision afterward.
The test suite verifies due jobs, disabled jobs and connector locking.

### Incremental

Look for the newest `demo_incremental_<timestamp>` source. Preparation proves:
**3 initial rows → 0 unchanged rows → 2 changed rows → 4 unique stored users**.
Open `/connectors/<that-id>/sync-state` in the same signed-in browser to inspect
the checkpoint. The synthetic vendor was advanced by the setup script.
This requires a documented vendor change-window contract; it is not automatically
available for every vendor. Failed/quarantined runs do not advance the checkpoint.

## 13. Repeated-failure email notifications — B-4

The automated suite uses a local SMTP capture and verifies threshold, tenant routing,
cooldown, recovery, retry caps and opt-out. No real mailbox is contacted by those tests.
The prepared jury dashboard does not configure an SMTP recipient, so do not claim
that a live email was delivered from this account. Existing setup instructions are
in `docs/BONUS_B4_B5.md` and `scripts/smoke-notifications.ps1`.

## 14. Vendor map versus customer KEV alerts

**Vendor map** is Mohit's company/ownership research view, separate from exact
customer finding correlation. Its Wikidata calls depend on external availability.
Acquisition/incident web research requires Gemini search; Groq cannot provide that
capability. The server now rejects unsupported research before spending a budget
reservation. Use **KEV alerts** for the customer-specific CVE demonstration.

## 15. Short explanation to say aloud

“We built a Go engine that reads a config, checks access and credentials, calls a
vendor safely, follows pages, retries temporary failures, maps valid data into OCSF
and saves it in PostgreSQL. Invalid records go into quarantine without blocking
valid records. Each customer has isolated data and keys. We compare collected
vulnerability CVEs with CISA KEV, then use AI to explain a small verified evidence
set. AI can also draft configs and select a locally tested conversion repair.
Every AI request is metered per customer. The engine works with manual configs
when AI is unavailable.”

## Files added for this work, in simple terms

| File | Purpose |
|---|---|
| `internal/store/kev_matches.go` | Finds exact customer CVE matches against trusted CISA records. |
| `internal/api/kev_matches.go` | Exposes those matches to the signed-in customer's dashboard. |
| `internal/insights/question.go` | Bounds questions and rejects obvious secret/PII patterns. |
| `internal/ai/repair.go` | Asks AI to select from conversion choices already tested locally. |
| `internal/api/repair.go` | Samples, validates, previews, activates safely and reruns a repair. |
| `internal/store/migrations/015_config_repair.sql` | Lets the usage ledger record repair operations. |
| `internal/store/migrations/016_ai_research_reporting.sql` | Counts successful vendor research correctly in usage reports. |
| `configs/mock_vulnerabilities.json` | Maps clearly labeled synthetic asset findings for the demo. |
| `scripts/prepare-jury-demo.cjs` | Creates the local rehearsal data and checks the main flows. |
| `scripts/check-jury-ui.cjs` | Clicks through the real dashboard using headless Edge. |
| `tests/demo_flows_test.go` | Checks tenant KEV matching, questions, repair, metering and migration behavior. |
| `tests/customer_keys_test.go` | Checks multiple platform keys and shared customer budgets/isolation. |
| `tests/vendor_tokens_test.go` | Checks several vendor tokens concurrently without credential mixing. |

Existing changed files connect these pieces: API/IAM routes authorize actions;
SIEM builds approved evidence; the runner pins revisions; the UI displays the new
controls; OCSF exposes its existing base-type lookup for safe conversion selection.
