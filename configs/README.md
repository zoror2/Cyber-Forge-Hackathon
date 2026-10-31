# Connector config template

A new data source is **one JSON file**: no code change. Every record it produces is stored as an
**OCSF 1.9.0 event**: the common schema is [OCSF](https://schema.ocsf.io), pinned in
`pkg/ocsf/schema.json`.

Flow: `POST /configs` (draft) → `/configs/{id}/validate` → `/configs/{id}/activate` →
`/connectors/{id}/test` (one page, nothing written) → `/connectors/{id}/run` →
`GET /records/{ocsf_class}?source={id}`.

The file holds the **name** of a secret, never its value. Values are stored separately with
`PUT /secrets/{name}` and are bound to one host.

## Files here

| File | Source | Auth | Paging | OCSF class |
|---|---|---|---|---|
| [cisa_kev.json](cisa_kev.json) | CISA Known Exploited Vulnerabilities (**live**) | none | none (one document) | Vulnerability Finding (2002) |
| [github_members.json](github_members.json) | GitHub org public members (**live**) | bearer | Link header | User Inventory Info (5003) |
| [nvd_kev_cves.json](nvd_kev_cves.json) | NVD CVE API 2.0, KEV subset with CVSS (**live**) | api_key | offset | Vulnerability Finding (2002) |
| [mock_users.json](mock_users.json) | Local TLS mock (synthetic) | none | page number | User Inventory Info (5003) |
| [fixture_events.json](fixture_events.json) | Test fixture (synthetic) | none | none | Vulnerability Finding (2002) |

## Supported OCSF classes

| `destination.class` | class_uid | Identity field (upsert key, must be mapped `required: true`) | Other fields OCSF requires you to map |
|---|---|---|---|
| `vulnerability_finding` | 2002 | `finding_info.uid` | `vulnerabilities.0.cve.uid` (or another field inside `vulnerabilities.0`) |
| `detection_finding` | 2004 | `finding_info.uid` | none |
| `user_inventory` | 5003 | `user.uid` | none |
| `inventory_info` (devices) | 5001 | `device.uid` | `device.type_id` (constant `"0"` = Unknown is fine) |
| `authentication` | 3002 | `metadata.uid` | `user.*` |

`/validate` checks every mapping key against the official schema and lists any OCSF-required field
you missed, before anything runs.

**Set by the platform (you cannot map them):** `class_uid`, `class_name`, `category_*`, `activity_*`,
`type_uid`, `type_name`, `severity` (caption of `severity_id`), `metadata.version`,
`metadata.tenant_uid`, `metadata.source` (= config `id`), `metadata.processed_time` (fetch time),
`raw_data*` (raw vendor payloads are never stored).

**Defaults when not mapped:** `time` = fetch time, `severity_id` = 0 (Unknown),
`metadata.product.name` = config `name`, `activity_id` = Create (findings) / Collect (inventory).

## Template (every field)

```jsonc
{
  "version": 1,                       // format version, must be 1
  "id": "my_source",                  // a-z 0-9 _ -, unique per tenant; becomes metadata.source
  "name": "Human readable name",

  "request": {
    "method": "GET",                  // read-only platform: GET only
    "url": "https://api.vendor.com/v1/users",   // https only, no credentials or query string in the URL
    "params":  { "limit": "100" },    // non-secret query params (also server-side filters: state=open, severity=CRITICAL)
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

  "filter": [                         // optional, client-side: keep only matching vendor records (all must match)
    { "path": "knownRansomwareCampaignUse", "op": "equals", "value": "Known" },
    { "path": "dateAdded", "op": "within_days", "value": 30 }
    // ops: equals | not_equals | in (list) | exists (true/false) | within_days (1-3650)
    // dropped records are counted as "skipped" in the run, never silently lost
  ],

  "destination": {
    "class": "user_inventory",        // an OCSF class from the table above
    "activity_id": 2,                 // optional; must be in the class's activity enum
    "mapping": {                      // OCSF attribute path -> where the value comes from in the vendor record
      "user.uid":        { "path": "id", "required": true, "transform": "string" },
      "user.name":       { "path": "profile.firstName" },          // nested vendor values with dots
      "user.email_addr": { "path": "profile.email" },
      "user.type_id":    { "path": "role", "transform": "lookup",
                           "lookup": { "ADMIN": "2", "USER": "1" } },  // OCSF enum IDs; out-of-enum values are quarantined
      "user.ldap_person.last_login_time": { "path": "lastLogin", "transform": "datetime" }, // -> epoch ms
      "metadata.product.name":        { "constant": "Okta" },
      "metadata.product.vendor_name": { "constant": "Okta" },
      "unmapped.department": { "path": "profile.department" }       // vendor fields with no OCSF slot
      // arrays need an index:  "vulnerabilities.0.cve.uid"
      // transforms: string | trim | integer | datetime (+ format, timezone) | lookup
      // defaults:   { "path": "x", "default": "unknown" }
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

The real files are plain JSON. The `//` comments above are for reading only, so remove them before submitting.

## What a stored record looks like (CISA KEV, abridged)

```json
{
  "class_uid": 2002, "class_name": "Vulnerability Finding", "type_uid": 200201,
  "activity_name": "Create", "severity_id": 0, "severity": "Unknown", "time": 1793318400000,
  "finding_info": { "uid": "CVE-2026-118527", "title": "Ivanti Connect Secure … Vulnerability" },
  "vulnerabilities": [{ "cve": { "uid": "CVE-2026-118527" }, "cwe": { "uid": "CWE-340" },
                        "vendor_name": "Ivanti", "is_exploit_available": true,
                        "remediation": { "desc": "Apply mitigations …" } }],
  "unmapped": { "product": "Connect Secure", "ransomware_use": "Unknown", "due_date": "2026-11-13" },
  "metadata": { "version": "1.9.0", "tenant_uid": "tenant-a", "source": "cisa_kev",
                "processed_time": 1793452561450,
                "product": { "name": "Known Exploited Vulnerabilities Catalog", "vendor_name": "CISA" } }
}
```

A record that breaks a required mapping, an OCSF type or an enum goes to quarantine with the OCSF
field path and a reason. The rest of the page still lands.

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
- unknown JSON keys; mapping keys that aren't real OCSF fields; platform-owned OCSF fields; values outside OCSF enums

## Optional B-1 incremental sync

Supported vendor APIs can add an `incremental` time-window block. Use
[`mock_incremental_users.json`](mock_incremental_users.json) for the local TLS
demo and [`docs/BONUS_B1.md`](../docs/BONUS_B1.md) for the required lower/upper
filter and stable-pagination contract. This is opt-in; existing configs keep
full-sync behavior. Do not enable it on KEV or GitHub members without documented
modification filters.
