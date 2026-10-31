# KEV matching and AI drafts

## What changed

Mohit's CISA feed already worked. It discarded vendor/product during mapping.
We now keep those optional Event fields, with a `trim` transform, and identify
each connected tool with an optional config `vendor`.

`GET /exposure` joins live tenant connectors, reviewed vendor/product aliases,
that tenant's CISA events and the credential named by each connector. It returns
the vendor, connector, count, at most 20 CVE IDs/products, evidence fetch time,
and credential ID/name/owner. It never reads credential values or calls AI.

Example: a connector labelled `Ivanti` matches the reviewed KEV pair
`Ivanti` / `Endpoint Manager (EPM)`. The result says
`vendor_match_requires_deployment_review`. This is a vendor association: check
the actual product, deployment and version before deciding whether it is affected.
A KEV entry alone does not establish that a customer is vulnerable or a key must
be rotated. No key rotation or vendor-side action is automated.

The initial alias table has six exact pairs for Atlassian, GitHub and Ivanti.
It is deliberately incomplete. Add aliases through reviewed migrations; tenants
cannot edit it. Unknown pairs produce no match. Each tenant keeps its own KEV
copy for compatibility with the existing engine; shared reference ingestion is
deferred. Only events produced using CISA's canonical feed URL and expected field
paths count. The stored run's exact config revision provides that provenance.

Resync CISA after upgrading so existing rows acquire vendor/product. The engine
upserts; it does not delete CVEs absent from later feed snapshots. Results can
therefore contain historical entries. `evidence_fetched_at` tells reviewers how
old the evidence is. An empty result is not a claim that a customer is safe.

## Credential metadata

Migration 002 adds an opaque credential ID, owner, creator, last rotating actor,
host list and format marker. Owner/creator come from authentication, never a body
field. Phase 1 identities are opaque API-key principals, not people's names.
Legacy owners remain `legacy:unknown`; migration never invents a person.
Rotation preserves ID/owner/creator and records the new rotating actor.

Both single-value and multi-field inputs work:

```json
{"value":"<enter privately>","allowed_host":"api.vendor.example"}
```

```json
{"fields":{"client_id":"<enter privately>","client_secret":"<enter privately>"},
 "allowed_hosts":["auth.vendor.example","api.vendor.example"]}
```

Use exactly one value format and one host format. Hosts are exact; no wildcards,
duplicates or host rebinding. Values remain encrypted in both backends. The
existing encrypted envelope authenticates the canonical host list as well as
the tenant and secret name. Legacy single-value ciphertext still reads and can
be rotated into the new format. `GET /secrets` exposes metadata only.
The engine receives `NewSecretFields(...).WithID(...)`, so classified auth errors
identify the credential. Human accounts, notifications, credential sharing and
automated credential-health workflows remain future work.

## AI boundary

Groq is the first provider, selected by Prajwal. Default model:
`qwen/qwen3.8-27b`; model changes require tests. The adapter uses Groq's documented
[chat API](https://console.groq.com/docs/api-reference) with JSON output and our
own strict validator. [Groq documents](https://console.groq.com/docs/structured-outputs)
the difference between valid JSON and schema guarantees. We validate both syntax
and domain behavior independently.

Only reviewed files in [public_sources](../public_sources/README.md) are sent.
These contain public documentation excerpts and synthetic examples. The request
accepts source ID, local connector ID/name and consent; arbitrary docs, private
samples, secrets and tenant-selected URLs are rejected. Local ID/name are filled
after the provider returns and never sent to it. No prompt history/cache or
tenant-record lookup exists. An operator must review a new public source file
before it becomes available. This is the first onboarding boundary, not a
general private-document upload feature.

The model proposes only mapping, item path and pagination. It has no tools.
Unknown output fields, invented paths, bad dates, unsupported transforms,
oversized output, truncated responses, refusal and tool calls are rejected.
The app fixes the destination/auth recipe, limits and disabled schedule. Public
documentation may still contain prompt injection; the architecture limits its
authority, but successful structural validation does not prove semantic accuracy.
The customer reviews the draft and tests it before activation.

`aidraft.Provider` is the adapter boundary for Mohit's future local model. A local
provider is not implemented. Private data must not simply be enabled on this
external route when it is added: design a separate explicit local-only input path
and repeat the privacy/tenant tests first.

## Limits and audit

AI is disabled unless the authenticated tenant is in `CB_AI_ENABLED_TENANTS`.
Each request also requires `external_ai_consent:true`. Emptying the allowlist is
the kill switch (restart API). Concurrency is one draft per tenant/two globally
per process. The PostgreSQL daily budget is atomic across replicas/restarts,
defaults to 20 calls per UTC day, and can be set to 1–100. Failed calls count.
Each call has a 45-second deadline, 4096 completion-token cap, 24 KiB public-source
cap, 128 KiB response cap and 32 KiB plan cap. Calls are not automatically retried.

Migration 003 adds RLS-protected usage/audit tables. Audit contains request ID,
authenticated actor, source/model/prompt version, source/output hashes and fixed
outcomes; never prompt contents, private names, draft contents or values. Runtime
can insert/read audit events but cannot update/delete them. The trusted migration
owner retains administrative access. A process crash may leave a `requested`
event without a terminal event. Logs are not external tamper-proof storage.

## Local demo

Keep these in private `.env`; the exported example contains no key:

```dotenv
GROQ_API_KEY=<enter privately>
CB_AI_ENABLED_TENANTS=tenant-a
CB_AI_MODEL=qwen/qwen3.8-27b
CB_AI_DAILY_LIMIT=20
CB_AI_SOURCES_DIR=public_sources
```

Apply migrations using the bootstrap command before starting the API. Start the
API/TLS mock as in README. Keep all listening addresses on localhost.

```powershell
# A public CISA description goes to Groq; no customer data is sent.
.\scripts\draft-config.ps1 -Source cisa_kev -ConnectorId kev_draft -OutFile data/kev-draft.json -ConsentToExternalAI
# Inspect/edit the downloaded JSON, then save and test its draft revision.
.\scripts\test-draft.ps1 -ConfigFile data/kev-draft.json
```

The second command makes a bounded real request to CISA over HTTPS (outbound
internet required), accepts at most 100 sample rows and stores no records/run
history/quarantine/schedule state. It leaves the config as a draft. Existing
`POST /connectors/{id}/run` still executes live DB configs only. Activation is a
separate deliberate `POST /configs/{id}/activate` with `{"revision":N}`.

To test completely offline, use `configs/mock_users.json` with the local TLS mock
URL and allowed port 8081. AI drafting itself requires Groq internet access.
Postman has a separate KEV/AI collection so ordinary local tests do not spend
provider tokens or call public vendors accidentally.

## Verification

- Mohit's main `91b67ff`: full PostgreSQL/race/vet/build gate passed before merge.
- Trim/vendor/product tests passed; existing config/string behavior preserved.
- Exposure fixtures: tenant isolation, credential ownership, immutable hosts,
  source provenance, CVE format, deduplication, 20-ID cap, pagination, no-match.
- AI: consent/kill switch, upload rejection, invalid/injected output, limits,
  provider auth/failures/redirects/timeouts/truncation/refusal/tool calls; no writes
  from generation and no production writes from draft preview.
- Real PostgreSQL: migration from version 1, repeat migration, legacy ciphertext
  retrieval/rotation, metadata stability, append-only audit and atomic quotas.
- Live Groq: GitHub and KEV drafts passed validation and mapped all public fixture
  rows using Qwen. No claim that every new vendor draft will be correct.

Final verification on 2026-10-31: formatting, vet, the complete race-enabled Go
suite with real PostgreSQL, all five Windows command builds and all five static
Linux/amd64 builds passed. The compiled localhost smoke passed (25 unique users,
then two accepted/two quarantined). The two Postman collections passed 44/44 and
6/6 assertions respectively, zero failures. The downloaded live Groq KEV draft
also passed a real CISA preview: 100 accepted, zero quarantined, still inactive.
Compose config validation passed; actual Docker execution, live AWS/KMS and the
future local model remain unverified.
