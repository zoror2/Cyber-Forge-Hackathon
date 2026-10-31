# Handoff to Member B

From Member A (Mohith). Everything you need to build the data side and the API on top of the request-side engine.

Read first: [README](../README.md) → [WORK_SPLIT.md](WORK_SPLIT.md) → this file → [REQUEST_SIDE.md](REQUEST_SIDE.md) for internals.

---

## 1. What already exists

| Package | You use it for |
|---|---|
| `internal/engine` | `Fetch()` pulls every page of raw records for one connector |
| `internal/egress` | `Policy`: the outbound security rules (you only *configure* it, per environment) |
| `cmd/mockvendor` | Fake vendor to test against (500s, 429s, hangs, bad records, ...) |

All of it is Go standard library only. Run `docker compose --profile tools run --rm test` to see it pass.

**Your scope (from WORK_SPLIT.md):**
- B1: config schema
- B2: mapper + quarantine
- B3: Postgres
- B4: secrets backend
- B5: scheduler
- B6: HTTP API + health page
- B7: Postman collection
- B8: compose services

---

## 2. Contracts you must implement or use

### 2.1 `SecretStore`: you implement this (B4)

```go
// internal/engine/secret.go
type SecretStore interface {
    Get(ctx context.Context, tenantID, name string) (Secret, error)
}

func NewSecret(value string, allowedHosts ...string) Secret
```

Rules for your backend:

- **Multi-tenant:** secrets are looked up by **(tenant, name)**. Two tenants may both have a secret called `crowdstrike`; they must never resolve to each other's. Encrypt each tenant's secrets with **that tenant's own KMS key**.

- **Every secret is stored with a list of exact allowed hosts**, usually one (e.g. `api.github.com`, or `mockvendor:8081` for the mock in dev). Two only when a vendor needs it (Wiz: `auth.app.wiz.io` + `api.us17.app.wiz.io`). **No wildcards**: reject `*` at write time (the engine refuses them too). No host means unusable.
- Show the host list to the approver in the two-person review. A secret's hosts and the connector's `allowed_ports` are security decisions, not details.
- Return secrets **only** via `engine.NewSecret(value, hosts...)`. Never put raw values in your own structs, logs or errors.
- **Write-only API:** `PUT /secrets/{name}` accepts `{value, allowed_hosts: [..]}` and returns 204. `GET /secrets` returns names, hosts and timestamps, **never values**. No endpoint ever returns a value.
- **Startup check:** outside dev, the API's `main()` must call `policy.ProductionSafe()` and exit if it errors.
- **Two backends, one interface:**
  - **dev:** env vars or a local encrypted file. Never a plaintext file in the repo.
  - **prod:** AWS Secrets Manager (phase 2 wiring). The app's IAM role can *read*; changing a host binding is a separate admin action.
- Unknown name → return an error. The engine wraps it as `secret "<name>": <your error>`, so don't put the value or other secrets in your error text.

### 2.2 `Connector`: your config embeds or converts to this (B1)

```go
// internal/engine/spec.go (request side only)
type Connector struct {
    TenantID   string     `json:"tenant_id"`   // set by the platform from the session / DB row, never from user input
    ID         string     `json:"id"`          // tenant_id and id: [a-z0-9][a-z0-9_-]{0,63}
    Request    Request    `json:"request"`     // url, params, headers, timeout_seconds (GET only)
    Auth       Auth       `json:"auth"`        // type + secret NAME (+ header/username/token_url/client_id/scopes)
    Pagination Pagination `json:"pagination"`  // none | page | offset | link | cursor
    ItemsPath  string     `json:"items_path"`  // dotted path to the record array, "" = root
    Limits     Limits     `json:"limits"`
    Retry      Retry      `json:"retry"`
}
func (c Connector) Validate() error  // returns ALL problems via errors.Join
```

Your full config adds what the engine doesn't own: **name, entity type (user/device/event), field mapping, schedule, status (draft/approved/live), version.** Suggested shape:

```go
type ConnectionConfig struct {
    engine.Connector            // request side (A)
    Name     string
    Entity   string             // user | device | event
    Mapping  map[string]Field   // common-schema field -> path/transform
    Schedule Schedule           // interval
    Status   string             // draft | approved | live
    Version  int
}
```

Validation = `cfg.Connector.Validate()` **plus** your own mapping/schedule checks, joined into one error list. That covers bonus B-2 (clear errors before running).

### 2.3 Running a connector

```go
eng := engine.New(secretStore, policy, logger) // create once, reuse; safe for concurrent Fetch calls

res, err := eng.Fetch(ctx, cfg.Connector, func(p engine.Page) error {
    for i, raw := range p.Items {
        rec, mapErr := mapRecord(raw, cfg)      // your mapper (B2)
        if mapErr != nil {
            quarantine(cfg.ID, runID, p.Number, i, mapErr) // keep going (FR-9)
            continue
        }
        upsert(rec)                              // keyed by source + entity + external id (B3)
    }
    return nil // returning an error stops the run
})
```

Details that matter:

- **`p.Items` is raw decoded JSON** (`map[string]any`, `[]any`, `string`, `bool`, `nil`, and numbers as **`json.Number`**, not `float64`). Convert explicitly in the mapper; large IDs stay exact this way.
- **Partial runs:** pages already passed to your callback stay stored even if a later page fails. Record the run as `partial`, not `success`.
- **`res`** gives `Pages` and `Items` for the `runs` table.
- Set `source` and `fetched_at` on **every** stored record (PRD requirement).

### 2.4 Turning errors into run status (FR-10 health)

```go
switch {
case err == nil:                              status = "success"     // or "completed_with_errors" if anything was quarantined
case errors.Is(err, egress.ErrBlocked):       status = "blocked"     // SECURITY: alert, possible misuse
case errors.Is(err, engine.ErrPageLimit):     status = "partial"
case errors.Is(err, engine.ErrTooLarge):      status = "failed"
case errors.Is(err, context.DeadlineExceeded): status = "timeout"
default:
    var se *engine.StatusError
    if errors.As(err, &se) && (se.Code == 401 || se.Code == 403) {
        status = "auth_failed" // wrong or expired key
    } else {
        status = "failed"
    }
}
lastError := err.Error() // already redacted: no tokens, no query strings, no bodies
```

Store `err.Error()` as-is. **Never** store or display raw vendor responses.

### 2.5 Egress policy per environment (B6, the API's `main`)

Production uses the zero value `egress.Policy{}`. Dev needs to reach the mock vendor on the Docker network over plain HTTP. Wire it like this **and refuse to start if dev overrides appear in production**:

```go
policy := egress.Policy{}
if os.Getenv("CB_ENV") == "dev" {
    // e.g. CB_DEV_ALLOW_PRIVATE=172.16.0.0/12  (docker compose network)
    for _, p := range strings.Split(os.Getenv("CB_DEV_ALLOW_PRIVATE"), ",") {
        if p = strings.TrimSpace(p); p != "" {
            policy.AllowPrivate = append(policy.AllowPrivate, netip.MustParsePrefix(p))
        }
    }
    policy.AllowHTTP = os.Getenv("CB_DEV_ALLOW_HTTP") == "1"
} else if os.Getenv("CB_DEV_ALLOW_PRIVATE") != "" || os.Getenv("CB_DEV_ALLOW_HTTP") != "" {
    log.Fatal("dev egress overrides set outside CB_ENV=dev: refusing to start")
}
```

Note: `Connector.Validate()` requires `https://` URLs, so in dev either run the mock behind TLS or we add a dev-only relaxation together. **Decide this with me before changing validation; don't weaken it alone.**

---

### 2.6 Multi-tenant rules (decided: one shared platform for all customers)

All customers' data and vendor keys live in one database and one app, so isolation must be **enforced by the system**, not remembered:

| # | Rule | Where |
|---|---|---|
| 1 | Every table has `tenant_id`; **Postgres row-level security (RLS)** policies filter on it. The app connects as a role that **cannot bypass RLS**, and sets the tenant per transaction (`SET LOCAL app.tenant_id = $1`). | B3 |
| 2 | **Tenant comes from authentication only** (phase 1: the API key belongs to one tenant; phase 2: SSO session). Never from a URL, body field or header the caller controls. | B6 |
| 3 | Unique keys include the tenant: `(tenant_id, source, external_id)`, `(tenant_id, connector_id)`. | B3 |
| 4 | Secrets looked up by `(tenant, name)`, one **KMS key per tenant**. | B4 |
| 5 | Scheduler locks keyed by **tenant + connector**; per-tenant concurrency limits so one tenant can't starve others. | B5 |
| 6 | `tenant_id` on every log line, run row, quarantine row and audit entry. | all |
| 7 | **Isolation tests**: authenticate as tenant A and try to read or run tenant B's configs, records, runs, quarantine and secrets through every endpoint. Every attempt must return 404. | B6/B7 |

The engine already does its part: secret lookups and OAuth token caches are scoped to tenant + connector (tests `TestTenantsNeverShareOAuthTokens`, `TestTenantCannotUseAnotherTenantsSecret`).

**Phase 1 API auth with tenants:** replace the single admin token with **API keys stored hashed (SHA-256) in an `api_keys` table, each belonging to one tenant**. The key identifies the tenant. Compare in constant time.

### 2.7 How customers connect a tool (drives your API and UI)

1. The customer's admin creates a **dedicated read-only API credential** in the vendor console (a service account or API client, never a person's own login). Each vendor template will carry these setup steps.
2. In our UI they pick the vendor template, enter host/region and IDs, and paste the credential into a **write-only secret field**.
3. **Test connection** makes one real call and returns a count or a clear error.
4. Draft → approved by a different person → live → scheduled pulls.
5. Expired or revoked credential: the run status is `auth_failed`, health shows it, and the customer pastes a new one (rotation without downtime).

Configs are stored as **JSON** (Postgres `JSONB`). The generic config shape (auth blocks `static` / `oauth2` / `session` / named signers, connection types `https_pull` / `collector` / `syslog_receive`) is being designed next; agree it with Member A before building config storage.

## 3. Your tasks, with the security requirements

### B1: Config schema + validation
- Strict JSON decoding: reject unknown fields (`DisallowUnknownFields`).
- Size-limit request bodies (e.g. 256 KB).
- Return all errors at once.

### B2: Mapper + quarantine
- Rename fields, follow nested paths (`profile.login`), convert dates to UTC.
- Handle `json.Number`.
- A bad record goes to quarantine with a **reason**, connector, run ID and page/index. The run continues.
- Quarantine holds vendor data, which may include PII: store a **size-capped** copy of the raw record (e.g. 8 KB), protect it like the main tables, and include it in the retention policy.

### B3: Postgres
- Tables:
  - `configs` (versioned, with status)
  - `credentials_meta` (name, allowed host, timestamps; **no values**)
  - `users`, `devices`, `events`: common schema + `source` + `fetched_at`, unique on `(source, external_id)`
  - `quarantine`
  - `runs`: connector, started, finished, status, pages, items, quarantined, last error
  - `sync_state`
- **Parameterized queries only**, never string-built SQL.
- Migrations in the repo, applied on startup or via a command.
- Credentials for the database come from env / the secrets manager, never from the repo.

### B4: Secrets backend
See §2.1.

### B5: Scheduler
- Runs each `live` config on its interval.
- **Postgres locks** (`pg_try_advisory_lock` per connector, or `SELECT … FOR UPDATE SKIP LOCKED`) so a connector never runs twice at once, even with multiple instances later.
- Writes a `runs` row on start and updates it on finish.

### B6: HTTP API + health page
- Endpoints are frozen in [WORK_SPLIT.md](WORK_SPLIT.md#api-tested-in-postman).
- **Tenant-bound API key on every endpoint** (see §2.6): stored hashed, compared with `crypto/subtle.ConstantTimeCompare`. Return 401 without detail. Another tenant's resource returns **404**, never 403, so IDs can't be probed.
- **Never unauthenticated, even in dev.** The token gets replaced by SSO in phase 2; no backdoor stays behind.
- The engine runs **only `live` configs read from the DB**. `POST /connectors/{id}/run` takes an ID, never a config body.
- Body size limits, `http.Server` timeouts (`ReadHeaderTimeout` etc.), JSON errors without stack traces.
- `GET /health` as JSON **and** a simple HTML page (escape everything: `html/template`).

### B7: Postman collection
- Covers every item in the WORK_SPLIT "Phase 1 done criteria".
- **No real tokens in exported collections or shared workspaces.** Use Postman Vault / local env values.

### B8: Compose
Add to `docker-compose.yml`:
- `postgres`: password from a gitignored `.env`; no host port, or `127.0.0.1` only.
- `api`: `build.args.CMD: api`; `CB_ENV=dev`, `CB_DEV_ALLOW_PRIVATE=172.16.0.0/12`, `CB_DEV_ALLOW_HTTP=1` **only in the compose file, never in prod configs**; `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`.

Build your binary at `cmd/api/main.go`. The existing `Dockerfile` already builds any `cmd/<name>`.

---

## 4. Testing against the mock vendor

```bash
docker compose up -d --build mockvendor
```

From inside the compose network the mock is `http://mockvendor:8081`; from your machine it's `http://127.0.0.1:8081`. A secret for it is bound to host `mockvendor:8081`.

Example connector for the mock's offset endpoint:

```json
{
  "id": "mock_issues",
  "request": { "url": "http://mockvendor:8081/issues" },
  "auth": { "type": "none" },
  "items_path": "issues",
  "pagination": { "type": "offset", "offset_param": "startAt", "size_param": "maxResults", "page_size": 10 }
}
```

Note the `http://` versus validation point in §2.5.

---

## 5. Review requests

Per the two-person rule:

- **Please review my code:** `internal/egress/*`, `internal/engine/auth.go`, `secret.go`, `redact.go`. Try to break the egress guard; that's the most valuable review.
- **I'll review yours:** the secrets backend (B4) and the API auth (B6).

---

## 6. Open items to decide together

1. **Remove the legacy Python** (`configbridge/`, `tests/`, `configs/`, `pyproject.toml`) once your mapper/store replaces it.
2. **https vs the dev mock** (§2.5): a TLS mock, or a dev-only validation relaxation.
3. **Target integration list grew** (see README → Target integrations). Many tools need session login, POST searches, XML, and syslog push from on-prem networks. The data side should expect:
   - **higher volumes** (SIEM/firewall events)
   - **async search jobs**
   - possibly an **on-prem collector** pushing to us

   Design the `events` storage and the API with that in mind. Analysis is in progress.
4. **Okta OAuth:** unverified whether client-secret OAuth works for Okta APIs (may need `private_key_jwt` or an SSWS API token).
5. **`devices` table:** none of the first sources produce devices. EDR integrations (CrowdStrike, Sophos, Trend) will.
