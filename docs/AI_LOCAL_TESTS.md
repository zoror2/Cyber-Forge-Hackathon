# AI local verification and remaining work

1 November 2026. No external Groq, Gemini or Bedrock request was made in this
round. Real Docker PostgreSQL and OpenSearch were used. The Go API/test processes
ran on Windows. A subsequent complete Docker application-image smoke test and
AI dashboard browser verification also passed; see [AI_USAGE.md](AI_USAGE.md).

## What passed

`tests/ai_workflows_test.go` exercises both actual Groq and Gemini adapters
against deterministic local HTTP model stand-ins. Each provider scenario checks:

1. Public product, dataset, scope and documentation enter the config drafter.
2. An unsupported POST proposal is rejected. The validator's feedback reaches
   the next model request; the corrected GET proposal passes config/evidence
   checks in round two.
3. The returned config is disabled and unsaved. A local user fills the real test
   endpoint, saves it, previews it, activates it and collects a stored record.
4. Synthetic security events are stored in PostgreSQL. Fixed rules derive six
   authentication failures and one source-reported high-severity event.
5. OpenSearch retrieves two matching findings; PostgreSQL validates the selected
   IDs before aggregate evidence crosses the model boundary.
6. The explanation cites the two supplied evidence IDs. Token accounting reports
   two requests: 66 simulated tokens for drafting/repair plus 33 for explanation.
   These are fixture usage values, not actual provider billing.
7. Another tenant cannot use those findings. A free-text/SQL question field is
   rejected without another model request. Private notes, connector/tenant names,
   source descriptions, example user/IP data and API credentials do not enter
   either provider's prompts.

The complete local scenario took about 2.34 seconds for the Groq adapter and
2.36 seconds for the Gemini adapter. These timings include database/index work
and simulated HTTP answers; **they cannot compare hosted model speed**.

Existing tests also cover fabricated/wrong-scope config proposals, invented
fields/citations, missing documentation, bounded repairs, private documentation
destinations, provider redirects, unknown usage, bad search results, stale or
foreign findings, consent, budgets and model/provider failures.

## Bug fixed in this round

The explanation parser previously accepted the first JSON document and ignored
trailing content. A regression test demonstrated that acceptance. The parser now
uses the same bounded strict JSON check as config input, rejecting duplicate
keys, trailing documents and excessive nesting. Whitespace-only summaries are
also rejected. Rejected answers retain reported usage rather than appearing free.

## Which feature to use

| Situation | Current supported path | Boundary |
|---|---|---|
| A known, reviewed integration | Manual reviewed config or the reviewed example flow; local inputs and preview | The reviewed AI flow still calls the model. Manual configs avoid that dependency. An example does not certify every API in that vendor's product suite. |
| A new vendor with public API docs | Guided, evidence-checked config drafting | Supported GET/JSON/auth/pagination/OCSF contract only. Review docs, fill private values locally and test before activation. |
| An invalid config | Deterministic config check; validator feedback repairs AI-generated proposals | A general conversational editor for arbitrary private configs is not implemented. Do not send raw private configs/secrets to a hosted model. |
| Explain failed/degraded collection | Insights topic `connection_health` | Aggregate counts and approved error categories, not an inferred replacement URL or credential. |
| Explain current security signals | Insights topic `security_findings` | Five implemented rules, a 24-hour window and one connector. Findings are not proof of an attack or affected deployment. |
| Arbitrary SQL or broad natural-language questions across the database | Not implemented; request is rejected | Requires a separately designed, tenant-scoped query/evidence interface and its own evaluations. |

Go/PostgreSQL perform the fixed-rule aggregation. OpenSearch indexes and retrieves
the approved findings. The LLM explains selected evidence; it does not receive
database credentials, raw rows, a SQL tool or permission to change configs.
Citation and format validation cannot prove every sentence is semantically
correct. Model explanations remain explicitly subject to human review.

## Remaining checklist

- [ ] Run the same bounded, spaced public-doc cases against live Groq and Gemini.
  Compare first-pass validity, repair rate, correct real API collection, latency,
  reported tokens and quota/availability failures. Do not choose a provider based
  on simulated timings.
- [ ] Complete the generated-config-to-real-GitHub live proof. The earlier Gemini
  documentation check passed once; repeat attempts were invalid or rate-limited.
- [ ] Evaluate live explanations against known synthetic findings, including no
  evidence, misleading inputs and unsupported questions. Local stand-ins prove
  enforcement, not a model's resistance to prompt injection or hallucination.
- [ ] Push the verified changes to `member-b` once the required live release
  checks pass. No remote push or merge occurred during this round.
- [x] Verify the complete application image in Docker: API/bootstrap, TLS mock
  vendor, PostgreSQL, collection/upserts/quarantine and dashboard browser flows.
- [ ] Optional deployment proofs: live AWS IAM/Secrets Manager/KMS, Bedrock,
  external SMTP delivery and a real vendor incremental-sync contract. Local
  encrypted secrets, application IAM, SMTP capture and incremental contracts
  already have passing tests.
- [ ] Optional broader features: free-text database investigations, conversational
  private-config editing, background indexing/Sigma detectors, fleet-wide worker
  quotas and the extra enterprise-vendor adapters. These are not implemented or
  implied by passing the core FR/bonus tests.

Core FR-1 through FR-11 and bonuses B-1 through B-5 remain covered by local tests
within their documented scope; hosted AI reliability remains a separate release
check. See [VERIFICATION.md](VERIFICATION.md), [JURY_TESTS.md](JURY_TESTS.md)
and [VENDOR_TESTING.md](VENDOR_TESTING.md).

Evidence: `data/ai-response-validation.log`, `data/ai-local-workflows.log` and
`data/ai-local-full-gate.log` (ignored local files).

Final gate: **PASS**. Formatting, vet, race detection, the complete ordinary
suite with Docker PostgreSQL/OpenSearch and all six native builds passed.
The integration package took 116.679 seconds. Gitleaks and an exact-value scan
found no private credentials in candidate source files. Live provider comparison
was deliberately not run for that gate. Subsequent live observations are below.

```powershell
# Set disposable TEST_DATABASE_URL and local TEST_OPENSEARCH_URL first.
go test -v -count=1 ./tests -run '^TestAILocalWorkflowsThroughOpenSearch$'
go test ./internal/ai ./internal/insights
. ./scripts/check.ps1
```

## Subsequent live comparison (paused for dashboard work)

These are single observed tests, not a model benchmark or reliability guarantee.
The private runtime model was not switched.

| Provider/model | Evidence-based explanation | Generic config drafting |
|---|---|---|
| Groq Qwen | Rate limited on the tested prompt | Rate limited; not verified |
| Groq GPT-OSS 20B | Passed, 0.914 s, 1043 reported tokens | Provider rejected structured output |
| Groq GPT-OSS 120B | Passed, 3.448 s, usage unreported | Retry hit the tested 8000-token/minute quota |
| Gemini 3.8 Flash | Passed, 59.722 s, 701 reported tokens | Timed out in the tested flow |
| Gemini 3.5 Flash | Daily quota exhausted on repeat | No final generated-config collection proof |

GPT-OSS now requests low reasoning effort to fit its completion budget; that
specific adjustment has ordinary tests but has not had a new live comparison.
The user paused live testing and will supply fresh demo credentials later.
Fresh keys alone do not increase shared project/organisation quotas.

The customer consumption dashboard and operator comparison are implemented and
verified separately; they do not depend on live AI availability. See
[AI_USAGE.md](AI_USAGE.md). Currency estimates, editable customer-specific plans
and a general private-config chat remain outside this completed dashboard scope.
