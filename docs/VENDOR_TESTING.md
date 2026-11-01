# Vendor compatibility testing

Updated 1 November 2026. AI is excluded from these engine checks.

## Focus after the account-setup discussion

Do not create accounts for the entire product list. Existing real GitHub, NVD
and CISA tests already exercise collection and storage. The next useful targets
are Elastic locally and, if a sandbox is available, Sophos Central. Trellix is a
useful optional test when Mitigata already has a sandbox. An account with no
sample alerts/endpoints cannot prove successful record collection.

Elastic can be installed locally with [official Docker instructions](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-basic).
A local Elasticsearch search test using synthetic alert documents is not proof
of a complete Elastic Security detection/Kibana installation.

## Results so far

| Target | What passed locally | What remains |
|---|---|---|
| Elastic Security alert-search contract | HTTPS fixture, ApiKey header, offset pages, literal dotted fields, OCSF mapping, PostgreSQL storage, quarantine, repeat-run upsert, preview without persistence, tenant separation, bad-key failure and incomplete-response rejection | Actual Elastic account or local Elasticsearch service; real alert-index privileges/data. No live Elastic Security pass claimed. |
| Sophos Central endpoint contract | OAuth client-secret POST, token caching, tenant header, cursor pagination; documented endpoint shape maps to OCSF | Actual Central account with endpoint data. Discovery and live authentication are not verified. |
| Trellix EDR alert contract | Documented JSON:API alert shape maps to OCSF; JSON next-page URL traversal shares the engine's host/port/TLS guard | Actual gateway, API key and access token. Automated OAuth plus additional API-key header is not implemented by this manual-access-token profile. |
| GitHub, NVD, CISA | Previously verified with actual public APIs, supplied credentials where required, and PostgreSQL | Broader vendor coverage does not follow automatically from these passes. |

No new commercial-vendor live test has passed in this round. Missing accounts
are recorded as blocked, never counted as passing compatibility tests.

## Engine fixes exposed by these contracts

1. **Literal dotted keys:** source paths can now use RFC 6901 JSON Pointer.
   `/fields/kibana.alert.rule.name/0` addresses the literal field name, while
   `fields.kibana.alert.rule.name.0` retains the old nested-object meaning.
   Pointers support `~0` for tilde and `~1` for slash; invalid escapes fail
   validation. The mapper and collection/cursor reader use the same resolver.
2. **HTTP-200 incomplete/error envelopes:** optional `response_checks` compare
   explicit scalar values before any page is emitted. Elastic checks
   `timed_out=false` and `_shards.failed=0`; missing or mismatching values fail.
   Requesting `allow_partial_search_results=false` also asks Elasticsearch to
   reject shard failures. Checks are configured from the selected API contract,
   not automatically guessed for other vendors.
3. **OAuth client-secret POST:** `auth.client_auth_method` accepts
   `client_secret_post`; existing configs retain `client_secret_basic`. Secret
   form values are sent only over the existing guarded token connection.
4. **Next URLs in JSON:** `pagination.type=next_url` with `next_url_path` follows
   fields such as `links.next`. Cross-host/scheme changes, credential-bearing
   destinations, cycles and page overruns are refused. Empty intermediate pages
   with a next URL continue rather than silently losing later records.

References: [Elastic alert fields](https://www.elastic.co/docs/reference/security/fields-and-object-schemas/alert-schema),
[search API](https://www.elastic.co/docs/api/doc/elasticsearch/v8/operation/operation-search),
[fields response](https://www.elastic.co/docs/reference/elasticsearch/rest-apis/retrieve-selected-fields),
[URL source convention](https://www.elastic.co/docs/reference/elasticsearch/rest-apis/api-conventions),
[Sophos tenant setup](https://developer.sophos.com/getting-started-tenant/),
[Sophos pagination](https://developer.sophos.com/concepts/pagination/),
[Trellix alerts](https://docs.trellix.com/v1/docs/get-alerts),
[JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901).

### Limits of the example configs

- Elastic uses bounded `from`/`size`, not PIT + `search_after`. It is unsuitable
  for claiming complete large-volume or concurrently changing snapshots. Do not
  raise it past Elasticsearch's default 10,000-hit result window and call it a
  complete export. Use a reviewed stable-window/deep-pagination implementation
  for that requirement. The current example caps at 5,000 records and 50 pages.
- Sophos device type stays **Unknown**: a generic computer record does not prove
  whether it is a desktop or laptop. Its minimal profile omits OS mapping.
- Trellix severity stays **Unknown** until a reviewed translation of its `s0-s5`
  codes is provided. It maps event identity from `id`, not the reusable Hash_Id.
  The static access token must be replaced when it expires; no generic refresh
  mechanism is claimed.
- The examples are disabled and use placeholder hosts. Replace them locally,
  save credentials separately, validate and preview before activation.

## Live access, only when available

Put these values in private `.env`. Never commit them. If temporary credentials
were sent in chat, revoke them after the test. The tests use a disposable Docker
database and keep AI disabled.

| Test selection | Private variables |
|---|---|
| `elastic` | `CB_TEST_ELASTIC_URL` (Elasticsearch HTTPS origin), `CB_TEST_ELASTIC_SPACE`, `CB_TEST_ELASTIC_API_KEY` (encoded key with read access to that space's alert alias) |
| `sophos` | `CB_TEST_SOPHOS_API_URL` (regional origin), `CB_TEST_SOPHOS_TENANT_ID`, `CB_TEST_SOPHOS_CLIENT_ID`, `CB_TEST_SOPHOS_CLIENT_SECRET` |
| `trellix` | `CB_TEST_TRELLIX_API_URL` (gateway origin), `CB_TEST_TRELLIX_ACCESS_TOKEN`, `CB_TEST_TRELLIX_API_KEY` |

```powershell
. ./scripts/load-env.ps1 -Bootstrap
# Set this to your disposable Docker PostgreSQL test database, not production.
$env:TEST_DATABASE_URL = '<disposable admin DSN>'
$env:CB_VENDOR_LIVE = 'elastic' # or sophos / trellix
go test -v -count=1 -timeout=4m ./tests -run '^TestVendorLiveEngineAndStorage$'
```

Selecting a live vendor without its required variables fails the test. The live
proof collects at most two pages and reports an incomplete outcome when bounded;
it does not disguise that sample as a full synchronization. Production egress
rules remain active; private appliances/custom CAs need an explicit reviewed test
setup rather than disabling certificate verification.

Local regression evidence: `data/vendor-contracts-final.log` and
`data/vendor-elastic-contract.log`. The full gate also passed:
`data/vendor-full-regression-gate.log` (formatting, vet, race tests with real
Docker PostgreSQL/OpenSearch and all six native builds; integration package
119.866 seconds). Gitleaks and exact private-credential scans found no leaks.
Changes remain local; no remote push was made in this round.
Live tests are opt-in and their absence is
listed above. The push gate's test timeout was raised from 120 to 180 seconds
because the existing integration suite already took 117-119 seconds before the
new tests; production job/request timeouts were not changed.

## Remaining supplied list

These products are still **unverified**, not silently approved. Public contract
research is not a live test, and product editions matter. Obtain the exact
edition/version and its API reference before proposing an executable config.

| Product/group | Current blocker or next check |
|---|---|
| Seceon, Gurucul | Vendor export API specification and sandbox needed; an integrations marketing page is insufficient. |
| ManageEngine Log360 | Confirm on-prem versus Cloud. Cloud search includes POST operations and Zoho authentication; it is not covered by a plain GET config. |
| LogRhythm | Confirm REST API edition/version; deprecated SOAP documentation is not a valid substitute. |
| OpenText ArcSight | Confirm ESM/Logger/SaaS. Logger's documented session login is a separate workflow, including XML output. |
| Binary Search | Product unidentified; excluded until clarified. |
| Palo Alto Cortex XSIAM | Key ID/key alone is insufficient: the documented alert/query POST workflow also needs support. Advanced signed authentication must be treated separately. |
| Kaspersky EDR | Confirm edition. KSC OpenAPI uses POST/session workflows; current GET collection is insufficient. |
| Seqrite XDR | Tenant-specific export API documentation and data needed. |
| Trend Micro Vision One | Need current regional Workbench-alert contract, token and data. Generic next-URL mechanics are tested; no Vision One pass claimed. |
| Symantec Endpoint Security | Confirm cloud/on-prem API, entitlement and authentication contract. |
| Forcepoint DLP | Application authentication/JWT workflow and sample incident response required. |
| Symantec DLP | Confirm on-prem incident API versus Cloud DLP; they are different contracts. |
| Digital Guardian / Fortra DLP | Vendor-provided ARC/export API contract and sandbox needed. |
| Trellix DLP | Confirm DLP SaaS versus endpoint/ePO API; EDR tests do not establish DLP support. |
| Zscaler DLP | Confirm OneAPI versus legacy DLP workflow API, scopes and authentication. |
| Netskope DLP | V2 read token and actual dataexport/iterator contract needed; legacy query-string secret examples must not be copied. |
| Safetica | Confirm edition and a supported export API; no public contract was established. |
| Fortinet FortiGate | Actual appliance/version, trusted read-only API administrator, TLS and selected dataset needed. Management objects are not automatically security alerts. |
| Check Point | Management POST/session workflow needs explicit support. |
| Cisco Secure Firewall | Confirm FMC/FTD API and dataset; FMC token generation/refresh is vendor-specific. |
| SonicWall | Confirm SonicOS/NSM edition and authenticated-session flow. |
| Sophos Firewall | Direct appliance XML API differs from Sophos Central JSON API. Endpoint tests do not certify either firewall API. |
| Juniper SRX | Confirm Junos version and selected RPC/export; XML/RPC/syslog are not covered by JSON GET collection. |
| WatchGuard Firebox | Confirm local versus Cloud API and logging/export entitlement. |
| AWS Security Hub / GuardDuty | AWS request signing, POST and, for GuardDuty, finding-ID detail retrieval need an adapter. AWS vault support does not provide this collector. |
| Google Security Command Center | Authenticated findings-list contract, scope/location and data needed. Short-lived Bearer authentication alone does not provide automatic Google identity refresh. |
| Wiz | GraphQL query/variables and vendor auth require a dedicated reviewed collector path. |
| Prisma Cloud | Login/token and selected GET/POST alert pagination need exact contract verification. |
| Orca Security | Tenant API specification, viewer token and data needed; no unverified endpoint is guessed. |
| Lacework FortiCNAPP | Account/key ID/secret and its access-token/search workflow need explicit support. |
| CrowdStrike Cloud Security | Select a specific collection API: ID-query/detail hydration differs from combined-record endpoints. OAuth alone does not establish collector compatibility. |

Useful official references for confirmed gaps:
[ManageEngine search](https://www.manageengine.com/cloud-siem/api/v2/search/),
[KSC protocol](https://support.kaspersky.com/help/KSC/16.1/KSCAPI/index.html),
[Check Point management](https://sc1.checkpoint.com/documents/latest/APIs/),
[Security Hub GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html),
[GuardDuty ListFindings](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListFindings.html).

## Multiple vendor tokens (1 November 2026, IST)

`TestConcurrentVendorTokensRemainBoundToTenantAndConnector` checks four synthetic
GitHub-style Bearer tokens against a strict local TLS vendor with Link pagination.
Two customers each have `repo_one` and `repo_two`, and deliberately reuse secret
names `github_one` and `github_two`. Their secret values are different.

- All four first-page requests overlap; the vendor checks the exact assigned
  token on every page. Stored records remain scoped to the customer and source.
- Rotating one token leaves the other three working.
- An invalid token produces `auth_failed` after one vendor request; other tokens
  stay usable, and replacing the invalid value restores collection.
- A reference available only in another tenant fails as missing. A host-binding
  mismatch is blocked before any vendor request.
- Secret values are excluded from run/secret/quarantine responses and logs.

This proves credential routing in our engine, not live GitHub scopes or private
repository permissions. No real vendor PAT is used. Each connector uses its
configured secret reference; automatic PAT pooling/round-robin is not implemented.

`TestMultipleCustomerKeysShareUsageAndRemainIsolated` separately checks inbound
customer access keys: four keys, 24 concurrent reads, shared per-customer AI
usage/quota, audit attribution, role changes, immediate revocation and owner
deactivation. Customer access keys and outgoing vendor PATs are separate things.

Both checks can be rerun with `go test -race -count=1 ./tests -run
'TestConcurrentVendorTokens|TestMultipleCustomerKeys'` using disposable
`TEST_DATABASE_URL` and optional `TEST_OPENSEARCH_URL` test services. The sandbox
verification also runs the complete race-enabled suite inside the existing
Dockerfile's Go build stage, mounting only the tests directory read-only and
using the dedicated Docker PostgreSQL/OpenSearch services. It receives no real
API keys or private `.env` file.

Result: the full Docker gate passed vet, race-enabled tests and all command
builds; the integration package took 118.175 seconds. The test runner shares
OpenSearch's network namespace to use its approved development loopback URL.
The initial Docker-IP HTTP setup was correctly rejected by the search client's
security check; no application security rule was relaxed.
