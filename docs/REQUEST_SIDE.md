# Request side (Member A): what each file does

Everything that talks to a vendor API. Go standard library only, zero third-party dependencies.

```
go.mod                         module definition (no dependencies)
internal/egress/egress.go      WHERE a request may go
internal/egress/egress_test.go
internal/engine/spec.go        WHAT a connector config looks like + validation
internal/engine/secret.go      the Secret type that cannot be printed
internal/engine/auth.go        HOW credentials are attached
internal/engine/engine.go      fetch loop: retries, 429, pagination, limits
internal/engine/redact.go      strips URLs before they reach logs/errors
internal/engine/engine_test.go
cmd/mockvendor/main.go         fake vendor for failure testing (never deploy)
Dockerfile                     builds any cmd/ into a tiny non-root image
docker-compose.yml             test runner + mock vendor
.dockerignore / .gitattributes build hygiene
```

## `internal/egress/egress.go`: the security gate

Every outbound request passes through here. It refuses anything that could leak a secret or reach inside our network.

| Function | What it does |
|---|---|
| `Policy` | The rules. The zero value is production. `AllowPrivate`, `AllowHTTP` and `RootCAs` exist **only** for local dev/tests (mock vendor, test servers). |
| `CheckURL` | HTTPS only; no `user:pass@` inside URLs; host must exist. |
| `CheckSecretHost` | A secret goes **only** to the exact host it is bound to. `api.github.com.evil.com`, `sub.api.github.com` and other ports are all refused. |
| `CheckIP` | Refuses loopback, private (10/172.16/192.168), link-local (incl. `169.254.169.254` cloud metadata), CGNAT, multicast, IPv6 equivalents and IPv4-in-IPv6 tricks. |
| `Client` | The HTTP client the engine must use. It checks the **actual IP at connect time** (after DNS), so `evil.com → 127.0.0.1` fails. It never follows redirects, ignores proxy env vars, and uses TLS 1.2+ with header size and timeout limits. |
| `ErrBlocked` | Marks every refusal. The engine never retries it and logs it at ERROR level. |

## `internal/engine/spec.go`: the connector config (request part)

The shape of the request half of a config, plus validation. **Member B owns the full config** (mapping, schedule) and embeds or converts to `Connector`.

| Type / function | What it does |
|---|---|
| `Connector` | id, request, auth, pagination, `items_path` (where the record array sits in the JSON), limits, retry. |
| `Request` | URL, GET only (read-only platform), non-secret params and headers, timeout. |
| `Auth` | Auth type plus the secret **name**. It never holds a secret value. |
| `Pagination` | `none`, `page`, `offset`, `link` or `cursor`, and their parameter names. |
| `Limits` / `Retry` | Max response size, pages and run time; retry attempts, base delay, longest `Retry-After` we accept. |
| `withDefaults` | GET, 30s timeout, 10 MB, 1000 pages, 15 min run, 4 attempts (1s/2s/4s), 120s max Retry-After. |
| `Validate` | Returns **all** problems at once, for the UI. Rejects non-HTTPS URLs, unknown auth/paging types, missing fields, out-of-range limits, and **any header or query param whose name looks like a credential** (`Authorization`, `api_key`, `X-Auth-Token`...). This is how "secrets only via the auth block" is enforced. |
| `looksSensitive` / `splitWords` | Word-based matching, so `apiKey` is caught but NVD's `keywordSearch` is allowed. |

## `internal/engine/secret.go`: the unprintable secret

| Item | What it does |
|---|---|
| `Secret` | A value plus its one allowed host. The value sits inside a closure, so printing any struct that contains it shows a memory address, never the token. `String`, `%#v`, JSON, text and `slog` all print `[redacted]`. |
| `NewSecret(value, host)` | How Member B's secrets backend hands a secret to the engine. |
| `SecretStore` | **The contract with Member B**: `Get(ctx, tenantID, name) → Secret`. Secrets are per tenant. |

## `internal/engine/auth.go`: attaching credentials

| Function | What it does |
|---|---|
| `authorize` | Adds credentials to a request: `api_key` (custom header), `bearer`, `basic` (username + secret), or OAuth2. |
| `boundSecret` | Fetches a secret **and checks its bound host against this exact request URL** before it can be used. |
| `oauthToken` | OAuth2 client-credentials: sends the client secret only to the token URL's bound host, uses the access token only on that same host, caches tokens **in memory only**, refreshes 30s before expiry, and drops the cached token on a 401. |

## `internal/engine/engine.go`: the fetch loop

| Function | What it does |
|---|---|
| `New` | Builds an engine from a secret store, an egress policy and a logger. |
| `Fetch(ctx, connector, emit)` | **Main entry point.** Validates, enforces the run time limit, walks every page and hands each page's raw records to `emit` (Member B's mapper). Pages already emitted are kept if a later page fails. |
| `pagedURL` | Adds page, offset, cursor and size params to the URL. |
| `get` | One logical request with retries. |
| `retryDelay` | **The retry rules:** 5xx, 408 and network errors/timeouts back off 1s → 2s → 4s, then fail. 429 waits exactly `Retry-After` (seconds or HTTP date), but gives up if the vendor asks for longer than the max. Other 4xx (401/403/404), egress blocks and oversized responses are never retried. |
| `once` | A single HTTP attempt: sets headers, attaches auth, reads the body with a size cap, returns a `StatusError` (never the body) on non-2xx. |
| `readLimited` | Stops reading past the size cap, returning `ErrTooLarge`. |
| `decodeItems` / `getPath` | Parses JSON and finds the record array via a dotted path (`issues`, `data.items`). |
| `nextLink` / `splitLinks` | Parse the RFC 8288 `Link` header for `rel="next"` (GitHub, Okta). |
| Pagination safety | Next links pointing at a **different host are refused**; repeated URLs (loops) are detected; `max_pages` stops runaway paging. |
| `parseRetryAfter` | Handles both `Retry-After: 30` and the HTTP-date form. |
| `logFailure` | Logs failures with redacted URLs; egress blocks are logged at ERROR. |

## `internal/engine/redact.go`: keeping logs clean

| Function | What it does |
|---|---|
| `RedactURL` | Keeps only `scheme://host/path`: no query string, no credentials. |
| `scrub` | Go's HTTP errors embed the full URL; this swaps it for the redacted form and keeps the cause for `errors.Is`. |

## Tests

**`internal/egress/egress_test.go`**: about 20 blocked IP forms (including the metadata IP and IPv6 tricks); URL rules; secret-host matching including `api.github.com.evil.com`; `localhost` blocked at dial time; redirects to the metadata IP refused.

**`internal/engine/engine_test.go`**: runs against local TLS test servers:

| Area | Tests |
|---|---|
| Auth | Bearer sent only to the bound host (a mis-bound secret never reaches the server); API key; Basic; OAuth2 token fetched once and cached |
| Reliability | 5xx → 1s, 2s, 4s then fail; recovery after 2 failures; 429 waits 5s; a 999s Retry-After gives up; 401 not retried; timeout retried; oversized response refused |
| Pagination | page, offset (Jira-style), Link header (GitHub-style), cursor, off-host next link blocked, runaway page limit |
| Leak prevention | Validation rejects secrets in headers/params; word matching allows `keywordSearch`; Secret never prints through any path; logs and errors contain no token and no query string |

## `cmd/mockvendor/main.go`: fake vendor for Postman

A test tool that misbehaves on demand. **Never deploy it.**

| Endpoint | Behaviour |
|---|---|
| `/users?page=&per_page=` | 25 users, page numbers + `Link` header |
| `/issues?startAt=&maxResults=` | 25 issues, Jira-style offset |
| `/events?after=` | Cursor paging |
| `/secure` | 401 unless `Bearer mock-token` |
| `/flaky?key=&fail=N&code=500` | Fails N times, then succeeds |
| `/ratelimit?key=&retry_after=5` | One 429, then succeeds |
| `/hang?seconds=60` | Never answers in time |
| `/redirect` | 302 to the cloud metadata IP |
| `/huge?mb=50` | Huge body |
| `/malformed` | Records with missing or bad fields (for Member B's quarantine) |
| `/offhost` | Next link pointing at another host |
| `POST /reset` | Resets the flaky/ratelimit counters |

## Docker and build files

| File | What it does |
|---|---|
| `Dockerfile` | Two stages: builds `./cmd/<CMD>` with the Go 1.27 image, then copies only the binary into **distroless, non-root**. The mock vendor image is about 3.5 MB with no shell. TODO: pin base images by digest before production. |
| `docker-compose.yml` | `test`: gofmt + vet + race-enabled tests with **no network**. `mockvendor`: bound to `127.0.0.1:8081` only, read-only filesystem, all Linux capabilities dropped. Member B adds Postgres and the API service here. |
| `.dockerignore` | Keeps `.git`, `.env`, docs, PDFs and the old Python code out of the build context. |
| `.gitattributes` | Forces LF line endings so gofmt in Linux Docker doesn't fail on Windows checkouts. |
| `go.mod` | Module `configbridge`, Go 1.27, **no dependencies**. |

## Commands

```bash
docker compose --profile tools run --rm test   # format + vet + all tests, offline
docker compose up -d --build mockvendor        # fake vendor on http://localhost:8081
docker compose down                            # stop it
```

## Not done yet / open

- **Python `configbridge/` and `tests/`** from Milestone 1 are still on `main`. Remove them once the Go engine covers them (agree with Member B).
- **Okta OAuth**: I believe Okta's org authorization server requires `private_key_jwt` rather than a client secret for API scopes. This is unverified; check before relying on the Okta OAuth path. API-token (SSWS) auth may be needed instead.
- **Retry jitter**: delays are exactly 1s/2s/4s, as the PRD specifies. Add jitter later if many connectors hit the same vendor.
- **Dev policy wiring**: the API service (Member B) must set `AllowPrivate`/`AllowHTTP` from env only in dev, and **refuse to start** if they're set in production.
