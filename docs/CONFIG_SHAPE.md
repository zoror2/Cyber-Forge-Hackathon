# Config shape

How a vendor integration is described, and what an engineer enters per tenant.
Based on research into all 35 target vendors (section 9). Owners: Member A
(request side: layer 1 auth / request / pagination) and Member B (storage,
UI form, mapping, scheduler).

**Status:** design agreed by Member A. Member B to review before either side builds on it.

> **Scope (2026-10-31): PRD first.** The PRD requires FR-1..FR-11 and **3 real free-tier sources**.
> The common schema is **OCSF 1.9.0** (changed 2026-10-31, see D6). Everything here that
> goes beyond that (the 35 enterprise vendors, collector, multi-tenant extras) is
> **roadmap**, built after the PRD is met.


---

## 1. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **Two layers**: reviewed *vendor templates* + small *tenant connectors* | Engineers can't invent auth flows, POST bodies or secret destinations. Read-only stays meaningful even though many vendors need POST. |
| D2 | Templates are JSON files in the repo, **changed only by pull request** with two reviewers | Same review bar as code, because a template *is* behaviour. |
| D3 | Tenant connectors are JSON rows in Postgres (JSONB), entered via the UI form, two-person approved | No restart needed; tiny surface to review. |
| D4 | Request templating = **fixed placeholders only** (`{{secret.x}}`, `{{token}}`, `{{discover.x}}`, `{{window.start}}`...), no logic | No template engine (Jinja-style sandboxes have a history of escapes; Go's `text/template` has no sandbox). Logic that's really needed becomes a named Go **signer**. |
| D5 | Field mapping uses **CEL** (`github.com/google/cel-go`) | Non-Turing-complete, cost-limited, no I/O, used by Kubernetes for the same reason. JMESPath only extracts; inventing our own DSL is a trap. |
| D6 | Target schema = **OCSF 1.9.0** (changed 2026-10-31; was User / Device / Event) | One standard schema instead of a home-grown one: SIEMs / Security Lake ingest it unchanged, the pinned schema validates every mapping key at `/validate`, and PRD user/device/event shapes map to User Inventory / Device Inventory / Findings. Config key is `destination.class` (not `ocsf_class` as sketched below). |
| D7 | Cloud signing via official libraries: `aws-sdk-go-v2` (SigV4 + STS assume-role), `golang.org/x/oauth2/google` | Never hand-roll SigV4. This ends "stdlib only": dependencies are allowed when they are official vendor/Go-team libraries, pinned, and reviewed. |
| D8 | On-prem tools: **collector only**. The platform never calls private IPs, no per-tenant exception | A private IP on our side is *our* VPC. "Allow this tenant's CIDR" would let a tenant scan our network. |
| D9 | Self-signed TLS (on-prem firewalls, etc.): **pinned CA or SHA-256 fingerprint**, collector connections only. `insecure_skip_verify` does not exist | Cloud vendors use public CAs; turning verification off is never an option. |
| D10 | Platform is **read-only**. No actions (block IP, isolate host, create ticket) | Writes to customer systems = a different risk class. Out of scope. |

---

## 2. Layer 1: vendor template (`templates/<vendor>/<name>.v<N>.json`)

```json
{
  "template": "prisma_cloud_alerts",
  "version": 1,
  "vendor": "Palo Alto Networks Prisma Cloud",
  "category": "cloud_finding",
  "connection": "https_pull",

  "hosts": ["api.prismacloud.io", "api2.prismacloud.io", "api.eu.prismacloud.io"],
  "ports": [443],
  "secret_fields": ["access_key_id", "secret_key"],

  "auth": {
    "type": "session",
    "login":   {"method": "POST", "path": "/login",
                "json": {"username": "{{secret.access_key_id}}", "password": "{{secret.secret_key}}"}},
    "token_from": {"json": "token"},
    "apply":   {"header": "x-redlock-auth", "value": "{{token}}"},
    "ttl_seconds": 540,
    "refresh": {"method": "GET", "path": "/auth_token/extend"}
  },

  "request": {"method": "POST", "path": "/v2/alert",
              "json": {"limit": 100, "timeRange": {"type": "absolute",
                       "value": {"startTime": "{{window.start_ms}}", "endTime": "{{window.end_ms}}"}}}},
  "response": {"format": "json", "items_path": "items"},
  "pagination": {"type": "token", "token_path": "nextPageToken", "send_in": "json", "send_as": "pageToken"},
  "incremental": {"type": "time_window", "overlap_seconds": 300},

  "mapping": {"ocsf_class": "detection_finding", "fields": {
    "finding_info.uid":   "item.id",
    "finding_info.title": "item.policy.name",
    "severity_id":        "{'low': 2, 'medium': 3, 'high': 4, 'critical': 5}[item.policy.severity]",
    "time":               "int(item.alertTime)"
  }},
  "options": {"lookback_hours": {"type": "int", "min": 1, "max": 168, "default": 24}}
}
```

(Prisma login flow is verified; the alert path/body/pagination names above are illustrative until checked against the docs.)

### Template rules (enforced by a loader + tests in CI)
- `hosts`: exact hostnames only, no wildcards. The tenant picks one; secrets are bound to the template's hosts the tenant selected.
- `path` everywhere, never a full URL: the host always comes from the tenant's selection, so a template can't send anything off-host.
- Placeholders allowed **only** in header values, JSON/form bodies and query values that aren't secrets. `{{secret.*}}` is **refused in URLs/query strings** (it would end up in logs and proxies).
- `options` declare everything a tenant can set, with types and ranges. Unknown option = refused.
- Every template ships with a mock fixture and a test (section 8).

---

## 3. Layer 2: tenant connector (what the engineer enters)

```json
{
  "tenant_id": "acme",
  "id": "prisma_prod",
  "template": "prisma_cloud_alerts@1",
  "host": "api2.prismacloud.io",
  "secret": "prisma-prod",
  "schedule_minutes": 15,
  "options": {"lookback_hours": 24}
}
```

Collector connections add:

```json
  "collector": "acme-dc1",
  "host": "fw01.acme.local", "port": 443,
  "tls": {"pin_sha256": "9f86d081884c7d65..."}
```

Rules: `host` must be in the template's `hosts` (cloud) or is free-form only for `collector` connections (run inside the customer's network, never by us). `tenant_id` always comes from the logged-in session, never from the body. The template version is pinned; upgrading is an explicit, approved change.

---

## 4. Building blocks

### 4.1 Auth types
| `type` | Shape | Vendors |
|---|---|---|
| `none` | n/a | mocks |
| `static` | list of `{header, value}` with `{{secret.x}}` | FortiGate, Netskope, Orca, Trend Vision One, Log360, LogRhythm, Cortex standard key (2 headers), Elastic API key |
| `oauth2` | `token_path`, `client_auth: header\|body`, `scopes`, `scope_separator`, `extra_params` (e.g. `audience`) | CrowdStrike, Sophos Central, Trellix, Wiz, Digital Guardian, Symantec SES, Zscaler (secret variant) |
| `session` | `login` request, `token_from` (`json` path or `header`), `capture` (extra values, e.g. Cisco `DOMAIN_UUID`), `apply`, `ttl_seconds`, optional `refresh`, `logout`, optional second step (`exchange`) | Prisma, Cisco FMC, Check Point, Lacework, Forcepoint DLP (refresh → access), ArcSight, WatchGuard |
| `signer` | `name` + parameters; Go code, reviewed | `aws_sigv4` (assume-role + external ID), `gcp_service_account`, `cortex_advanced`, `oauth2_private_key_jwt` (Zscaler), `sonicos_digest` |

Client certificates (mTLS, Kaspersky KATA) are a TLS setting on the connection, not an auth type.

### 4.2 Requests
- `method`: `GET` or `POST` (POST only with a template-defined body). No PUT/PATCH/DELETE ever.
- body: `json`, `form`, or `graphql` (`query` + `variables`).
- `response.format`: `json` or `xml` (XML is converted to JSON first, then the same paths and CEL apply). XML parsing: no external entities, size-capped.

### 4.3 Pagination
| `type` | Covers |
|---|---|
| `none`, `page`, `offset`, `link` (RFC 8288), `cursor` | already in the engine |
| `token` (`token_path`, `send_in: query\|json`) | AWS `NextToken`, Google `pageToken`, Prisma |
| `next_url` (full URL in the body, must stay on the same host) | Trend Vision One `nextLink` |
| `graphql_relay` (`pageInfo.endCursor` / `hasNextPage` → `after`) | Wiz |
| `search_after` (sort values of the last item) | Elastic |
| `iterator` (server-side, `operation=next`) | Netskope |
| `bookmark_ack` (fetch → store → acknowledge) | Digital Guardian |
| `ids_then_details` (list IDs, fetch details in batches of N) | GuardDuty (50/50) |

### 4.4 Discovery (optional, runs before requests)
One template-defined call whose results are `capture`d as `{{discover.x}}`. If it returns a host, that host **must equal** the tenant's selected `host`, or the run fails. Sophos Central (`whoami` → tenant ID + region host), Cisco FMC domain.

### 4.5 Incremental state
Per connector, stored by Member B after a successful store: `time_window` (last end, with overlap), `cursor`, or `bookmark`. For `bookmark_ack`, acknowledge only **after** the batch is committed, or data is lost.

### 4.6 Mapping (CEL) to the PRD schema
- Input: `item` (one raw record). Output: one of the PRD's record types; the raw record is kept alongside.
- **User:** `id, name, email, status, source, last_login`
- **Device:** `id, hostname, ip, os, owner, source, last_seen`
- **Event / Alert:** `id, type, severity, timestamp, description, source`
- Every record also carries `source` and `fetched_at` (plus our provenance: `tenant_id, connector_id, credential_id, run_id`).
- FR-5 needs: rename fields, pick nested values, convert dates. CEL covers all three.
- Limits: expression length cap, CEL cost limit per record, no custom functions with I/O, compile at template load (a bad expression fails CI, not a run).
- Records that fail mapping go to quarantine (Member B), never silently dropped.

---

## 5. Connection types
| Type | Who connects | Vendors |
|---|---|---|
| `https_pull` | our engine → vendor cloud | most cloud vendors |
| `collector_pull` | customer-run collector → on-prem API, pushes results to us outbound | LogRhythm, ArcSight, Log360, Forcepoint DLP, Symantec DLP, Trellix ePO, Kaspersky, Cisco FMC, Check Point (on-prem), FortiGate, SonicWall, Sophos Firewall, Juniper SRX |
| `collector_syslog` | collector receives syslog/CEF/LEEF locally, forwards to us | firewall event logs (their REST APIs are mainly config/status; I haven't checked each one) |
| `webhook_receive` | vendor pushes to a per-tenant URL with a shared secret / HMAC | Safetica (no pull API found) |
| `object_storage` | engine reads a customer bucket/queue via a role we assume | Symantec SES events (S3/SQS/GCS), GuardDuty S3 export |

Collector design is separate and still to do (auth to us, update channel, TLS pins, what it may reach).

---

## 6. Secrets and credentials
- Multi-field: one secret = named fields (`client_id`, `client_secret`, `private_key_pem`...). Template `secret_fields` says which are required; the UI form is generated from it. **Built** (`NewSecretFields`).
- Still write-only, per-tenant KMS key, bound to exact hosts (`allowed_hosts`), no wildcards.

### 6.1 Credential record (metadata only, never the value)
Several people in one tenant can connect the same vendor with their own keys. Each key has a visible record next to the encrypted value:

| Field | Purpose |
|---|---|
| `credential_id` | stable ID; connectors reference it; engine reports it (`Secret.WithID`, **built**) |
| `label` | "Ravi's GitHub (security org)" |
| `template` | which vendor recipe it's for |
| `owner_user`, `created_by`, `created_at`, `rotated_by`, `rotated_at` | who added it, who fixes it, audit trail |
| `vendor_identity` | whose vendor account it is (from the vendor's "who am I" call) |
| `fingerprint` | HMAC-SHA256 of the value with a KMS-held key: detects duplicates/swaps, irreversible |
| `fields_present` | field **names** only, compared with the template's `secret_fields` |
| `status`, `last_error` | from engine `AuthError.Status`: `missing` / `incomplete` / `binding_mismatch` / `needs_reauth` / `insufficient_permissions`, plus `expiring` / `revoked` (platform-side) |
| `expires_at`, `last_used_at`, `last_success_at` | health and reminders |
| `used_by_connectors` | what breaks if it's revoked |

Never stored: values outside the encrypted store, OAuth access tokens (engine memory only), vendor response bodies, "last 4 characters" of keys.

Permissions: only the owner or a tenant admin rotates/deletes a credential; others can use it in a connector only if the owner shares it; everyone in the tenant sees metadata, nobody sees values.

### 6.2 Provenance
Every stored record carries `tenant_id`, `connector_id`, `credential_id`, `vendor_identity`, `run_id`, `fetched_at`, so "which key produced this alert" is always answerable without the key.

## 7. Security invariants (tests must prove each)
1. A tenant connector cannot change a URL path, method, body, auth flow or mapping.
2. A secret is only ever sent to a host it is bound to, never in a URL.
3. No private/metadata IP from the platform, ever; collector-only for on-prem.
4. TLS verification can't be turned off; self-signed only via pin, collector only.
5. Only GET/POST; POST only with a template body.
6. CEL can't loop, do I/O or exceed its cost limit.
7. Discovery can't redirect a run to a host the tenant didn't select.

## 8. How a template is "validated" (and what we may claim)
- **Level 1, contract-tested:** template + mock fixture built from the vendor's docs pass CI. Claim: "tested against the documented API contract".
- **Level 2, live-verified:** run against a real vendor tenant (trial/sandbox/customer), record date + API version. Only level 2 may be called "verified".
- AI may draft a template PR from vendor docs; it goes through the same review and tests. AI never creates or approves tenant connectors and never sees secrets.

---

## 9. Vendor research (2026-10-31): roadmap, beyond the PRD

The PRD's proof uses free-tier APIs (GitHub, Okta, Jira, NVD, AbuseIPDB, CISA KEV). The 35 vendors below are the product roadmap; most have no free tier.

✅ = auth pattern confirmed in vendor or reputable integration docs · ⚠️ = partial / third-party only · ❌ = no public API docs found

| Vendor | Auth | Connection | Paging / notes | |
|---|---|---|---|---|
| Elastic Security | static (API key) | https_pull or collector | POST search, `search_after`, 1000/page | ✅ |
| Seceon | ? | ? | no public API docs | ❌ |
| Gurucul | ? (token) | ? | REST guide only via portal | ❌ |
| ManageEngine Log360 | static (Bearer AuthToken) | collector | POST `/RestAPI/v1/alerts`, port 8095; **V1 deprecated, support ended Sept 2026**: need V2 docs | ⚠️ |
| LogRhythm | static (Bearer) | collector | port 8501 default | ⚠️ |
| OpenText ArcSight | session (login → authToken) | collector | legacy login sends creds in query: avoid, use POST variant | ⚠️ |
| Binary Search | ? | ? | product not identified, confirm the name | ❌ |
| Cortex XSIAM | static or signer `cortex_advanced` | https_pull | all POST | ✅ |
| Sophos Intercept X (Central) | oauth2 | https_pull | discovery `whoami` → region host + `X-Tenant-ID` | ⚠️ |
| Kaspersky EDR | session + mTLS + admin approval | collector | token 10h (KATA) | ⚠️ |
| Seqrite XDR | ? | ? | no public API docs | ❌ |
| Trellix EDR | oauth2 (comma-separated scopes) | https_pull | two IAM hosts seen: confirm per tenant | ✅ |
| Trend Vision One | static (Bearer) | https_pull | regional hosts; `next_url` paging | ✅ |
| Symantec Endpoint Security | oauth2 | https_pull + object_storage | events via S3/SQS/GCS; token URL unconfirmed | ⚠️ |
| Forcepoint DLP | session, two-step (refresh 1d → access 15m) | collector | | ✅ |
| Symantec DLP | session (forms) / basic | collector | | ⚠️ |
| Digital Guardian | oauth2 | https_pull | `bookmark_ack` export | ⚠️ |
| Trellix DLP | basic (ePO on-prem) / Bearer + API key (SaaS) | collector / https_pull | | ✅ |
| Zscaler DLP | oauth2 (secret or private-key JWT) | https_pull | Workflow Automation API path unconfirmed | ⚠️ |
| Netskope DLP | static (`Netskope-Api-Token`) | https_pull | `iterator` | ✅ |
| Safetica | n/a (pushes) | webhook_receive | webhook only, one per tenant | ⚠️ |
| Fortinet FortiGate | static (Bearer) | collector | trusted-hosts allowlist on device | ✅ |
| Check Point | session (`sid`, logout) | collector or https_pull (Smart-1 Cloud) | all POST, `show-logs` | ⚠️ |
| Cisco Secure Firewall (FMC) | session (Basic → header token, 30 min, 3 refreshes) | collector | captures `DOMAIN_UUID` | ✅ |
| SonicWall | signer `sonicos_digest` / bearer (2FA) | collector | | ⚠️ |
| Sophos Firewall | session-in-body (XML) | collector | XML, port 4444, IP allowlist on device | ⚠️ |
| Juniper SRX | basic | collector | XML RPC over POST | ✅ |
| WatchGuard Firebox | session (token) + API-key header | https_pull (WatchGuard Cloud) | log endpoint not found | ⚠️ |
| AWS Security Hub / GuardDuty | signer `aws_sigv4` + external ID | https_pull | `token`; GuardDuty `ids_then_details` | ✅ |
| Google SCC | signer `gcp_service_account` | https_pull | `token` (`pageToken`, max 1000) | ✅ |
| Wiz | oauth2 + `audience` | https_pull | GraphQL, `graphql_relay` (Wiz field names unconfirmed) | ✅ |
| Prisma Cloud | session (10 min, extend) | https_pull | | ✅ |
| Orca Security | static (`Authorization: Token`) | https_pull | POST serving-layer query | ⚠️ |
| Lacework FortiCNAPP | session (`X-LW-UAKS` → bearer) | https_pull | | ✅ |
| CrowdStrike Cloud Security | oauth2 | https_pull | regional hosts; rate limit via headers, no Retry-After | ⚠️ |

**Action items:** get API docs or portal access for Seceon, Gurucul, Seqrite and Binary Search (confirm the name); Log360 V2 docs; Symantec SES token URL; WatchGuard log endpoint; CrowdStrike alert paging.

## 10. Engine work this implies (Member A)
1. Multi-field secrets.
2. Template loader + validator (rules in section 2) + placeholder renderer.
3. Auth: `static` (multi-header), `oauth2` variants, `session`, signer registry.
4. POST + JSON/form/GraphQL bodies; XML → JSON.
5. New paging types (section 4.3) and discovery.
6. Current `Connector` becomes the *resolved* form (template + tenant connector merged) that `Fetch` runs.
