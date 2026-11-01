# Demo verification — 1 November 2026

Merged baseline: Mohit's `main` at `aa59250`; no merge conflicts. Its independent
Docker gate passed before implementation. The final gate passed **383 test
cases/subcases**, with **zero failures**, race detection, `go vet` and builds of
all six commands. Eight optional live/vendor cases were intentionally skipped
by the offline suite; unavailable commercial accounts are not certified.

## New behavior

- Exact, tenant-scoped CVE intersection of collected vulnerability findings and
  records produced by the trusted CISA feed contract. The dashboard displays
  matching source/record/run evidence; the AI receives a bounded validated CVE list.
- A typed question on Insights, explicit provider consent, input bounds/basic
  secret-pattern rejection and evidence-only answers without SQL/database access.
- AI-assisted conversion repair from Quarantine: local sample checks, bounded
  model selection, validation, preview, compare-and-swap activation and revision-pinned
  rerun. Unsupported/ambiguous repairs stop without replacing the live config.
- Registered Mohit's previously unregistered migration 14; added repair operation
  accounting and corrected successful research reporting. Groq web-research
  requests are refused before spending a budget reservation.

## Final application and browser checks

The existing Docker application was rebuilt and exercised on loopback. PostgreSQL,
TLS vendor fixture and OpenSearch are actual running services. Provider fixtures
are used in automated regression tests; the browser AI checks below use real Groq.

| Check | Result |
|---|---|
| Pagination/mapping/duplicate prevention | 3 pages, 25 users; repeated runs retain 25 unique records. |
| Preview | Samples 10 users without inserting records. |
| Quarantine | Mixed source: 2 accepted, 2 rejected. |
| Tenant separation | Second customer cannot read first customer's source/records/catalog. |
| Real CISA collection | 1,766 entries in the observed snapshot from CISA's official GitHub mirror. |
| Exact KEV correlation | 3 synthetic asset findings produce exactly 2 matches; unmatched CVE absent. |
| Real OpenSearch retrieval | Synthetic security events produce 6 recent failed logins and 1 recent high-severity finding. |
| Vendor credentials | Encrypted, exact host/port-bound Bearer request succeeds; secret listing excludes value. |
| Retry / rate limit | 5xx success after 3 attempts; 429/Retry-After success after 2 attempts. |
| Negative safety cases | Timeout, redirect refusal and response-size cap return the expected reasons. |
| Incremental | 3 initial, 0 unchanged, 2 changed; 4 unique users and committed checkpoint. |
| Typed SIEM question | Consent and obvious sensitive-input refusal work; real AI answer appears. |
| AI repair through UI | Preview, activation and actual rerun yield 25 accepted, 0 quarantined. |
| Manual wizard | Paste/check/preview/activate/fetch/display succeeds. |
| AI config template | Real GitHub public-contributors draft, official links, owner/repo inputs and credential gate pass. |
| Usage dashboards | Customer totals, protected platform view, tenant separation and no persisted operator token pass. |
| Browser errors | No JavaScript page errors in the completed checks. |

## Small live-provider measurements

Groq `qwen/qwen3.8-27b`, public/synthetic evidence only:

- Conversion-choice selection: approximately **0.21 seconds**, **101 reported tokens**.
- KEV question explanation: approximately **0.62 seconds**, **878 reported tokens**.

These are two observed calls, not a throughput guarantee or quota comparison.
Additional actual browser calls for questions, repair and the reviewed template passed.

## Evidence on this laptop

- `data/jury-release-gate.jsonl`: final full Docker vet/race suite/build command.
- `data/jury-demo-checks.json`: setup/API flow results.
- `data/jury-browser-checks.json`: full dashboard checks.
- `data/jury-draft-browser-checks.json`: additional live template check.
- `data/live-demo-check-2.log`: live latency/usage observations.
- `data/jury-*.png`: synthetic-data dashboard screenshots.

Runtime artifacts, private settings, certificates and keys are ignored by Git.
The guide and reusable demo scripts are committed; those private artifacts are not.

## Practical limits

AWS setup/deployment remains with Mohit. Real device/SIEM sensor ingestion and
commercial-vendor accounts were not supplied. Email alert delivery is verified
through local SMTP capture tests, not an external mailbox. Vendor ownership/
incident web research requires Gemini search; current Groq supports explanations,
reviewed/documented template assistance and constrained conversion repair.

KEV presence is a review signal, not proof of compromise or affected deployment.
Automatic repair is intentionally bounded to verified conversions; it does not
invent missing mappings, bypass credentials or correct invalid source facts.
