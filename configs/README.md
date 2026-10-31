# Connector config template

A new data source is **one JSON file**: no code change. Submit it with
`POST /configs`, check it with `/validate`, make it live with `/activate`, try it with
`/connectors/{id}/test` (one page, nothing written) and sync it with `/connectors/{id}/run`.

The file holds the **name** of a secret, never its value. Values are stored separately with
`PUT /secrets/{name}` and are bound to one host.

## Files here

| File | Source | Auth | Paging | Lands in |
|---|---|---|---|---|
| [cisa_kev.json](cisa_kev.json) | CISA Known Exploited Vulnerabilities (**live**) | none | none (one document) | `events` |
| [github_members.json](github_members.json) | GitHub org public members (**live**) | bearer | Link header | `users` |
| [mock_users.json](mock_users.json) | Local TLS mock (synthetic) | none | page number | `users` |
| [fixture_events.json](fixture_events.json) | Test fixture (synthetic) | none | none | `events` |

## Template (every field)

```jsonc
{
  "version": 1,                       // format version, must be 1
  "id": "my_source",                  // a-z 0-9 _ -, unique per tenant; becomes `source` on every record
  "name": "Human readable name",

  "request": {
    "method": "GET",                  // read-only platform: GET only
    "url": "https://api.vendor.com/v1/users",   // https only, no credentials or query string in the URL
    "params":  { "limit": "100" },    // non-secret query params
    "headers": { "Accept": "application/json" },// non-secret headers (secret-looking names are refused)
    "timeout_seconds": 20,
    "allowed_ports": [443]            // default [443]; any other port must be listed so the reviewer sees it
  },

  "auth": {
    "type": "none",                   // none | api_key | bearer | basic | oauth2_client_credentials | static
    "secret": "vendor_token",         // NAME of the stored secret (not the value)
    "header": "X-API-Key",            // api_key: header to put the key in
    "username": "me@company.com",     // basic: user name (the secret is the password / API token)
    "token_url": "https://auth.vendor.com/oauth2/token",  // oauth2: token endpoint
    "client_id": "",                  // oauth2: "" = take it from secret field client_id
    "scopes": ["read"],               // oauth2: optional
    "extra_params": { "audience": "x" }, // oauth2: extra non-secret token-request fields
    "headers": [                      // static: 1-5 headers built from secret fields
      { "name": "Authorization", "value": "SSWS {{secret.value}}" }
    ]
  },

  "items_path": "data.items",         // where the record array is in the response ("" = the response is the array)

  "pagination": {
    "type": "none",                   // none | page | offset | link | cursor
    "page_param": "page",  "start_page": 1,          // page
    "offset_param": "startAt",                       // offset
    "size_param": "limit", "page_size": 100,         // page / offset / cursor
    "cursor_param": "after", "cursor_path": "meta.next" // cursor
                                                     // link: nothing; follows the HTTP Link: rel="next" header
  },

  "schedule": { "enabled": false, "interval_seconds": 900 },  // e.g. every 15 minutes

  "destination": {
    "entity": "user",                 // user | device | event
    "mapping": {                      // common-schema field -> where to find it in a vendor record
      "id":         { "path": "id", "required": true, "transform": "string" },
      "name":       { "path": "profile.firstName" },          // nested values with dots
      "email":      { "path": "profile.email" },
      "status":     { "path": "status", "transform": "lookup",
                      "lookup": { "ACTIVE": "active", "SUSPENDED": "disabled" } },
      "last_login": { "path": "lastLogin", "transform": "datetime" }  // RFC 3339 by default
      // constants:   { "constant": "known_exploited_vulnerability" }
      // defaults:    { "path": "x", "default": "unknown" }
      // date only:   { "transform": "datetime", "format": "2006-01-02", "timezone": "UTC", "precision": "date" }
    }
  },

  "limits": {                         // safety caps against broken or malicious vendors
    "max_pages": 100, "max_records": 10000,
    "max_response_bytes": 10485760, "max_run_seconds": 300
  },

  "retry": {                          // 5xx / timeouts: 1s, 2s, 4s… ; 429: honours Retry-After
    "max_attempts": 4, "base_delay_ms": 1000, "max_retry_after_seconds": 120
  }
}
```

The real files are plain JSON. The `//` comments above are for reading only, so remove them
before submitting.

## Common schema fields

| Entity | Mappable fields | Required mappings |
|---|---|---|
| user | id, name, email, status, last_login | id |
| device | id, hostname, ip, os, owner, last_seen | id |
| event | id, type, severity, timestamp, description | id, type, timestamp, description |

`source` (= config `id`), `tenant_id` and `fetched_at` are added by the platform and cannot be mapped.
A record that fails a required mapping goes to quarantine with its page, index, field and reason.
The rest of the page still lands.

## Auth examples (one per type)

```json
{ "type": "api_key", "secret": "nvd_key", "header": "apiKey" }
{ "type": "bearer",  "secret": "github_token" }
{ "type": "basic",   "secret": "jira_token", "username": "me@company.com" }
{ "type": "oauth2_client_credentials", "secret": "okta_oauth", "token_url": "https://acme.okta.com/oauth2/v1/token", "scopes": ["okta.users.read"] }
{ "type": "static",  "secret": "okta_ssws", "headers": [{ "name": "Authorization", "value": "SSWS {{secret.value}}" }] }
```

Store the matching secret (never in this file or in Git):

```powershell
$v = Read-Host "token" -AsSecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($v))
$key = (Select-String '^CB_BOOTSTRAP_API_KEY=' .env).Line.Split('=',2)[1]
Invoke-RestMethod http://127.0.0.1:8080/secrets/github_token -Method Put `
  -Headers @{Authorization="Bearer $key"} -ContentType 'application/json' `
  -Body (@{value=$plain; allowed_host='api.github.com'} | ConvertTo-Json)
Remove-Variable plain, v
```

## What the platform refuses (by design)

- `http://` URLs, private/internal IPs, odd IP spellings, ports not in `allowed_ports`
- following redirects; next-page links pointing at another host
- a secret used on a host it is not bound to (`credential_binding_mismatch`)
- secrets in `params` / `headers`, or `{{…}}` anywhere except `auth.headers`
- responses over `max_response_bytes`
- unknown JSON keys (a typo fails validation instead of being ignored)

## Optional B-1 incremental sync

Supported vendor APIs can add an `incremental` time-window block. Use
[`mock_incremental_users.json`](mock_incremental_users.json) for the local TLS
demo and [`docs/BONUS_B1.md`](../docs/BONUS_B1.md) for the required lower/upper
filter and stable-pagination contract. This is opt-in; existing configs keep
full-sync behavior. Do not enable it on KEV or GitHub members without documented
modification filters. AI drafting does not invent or enable these settings.
