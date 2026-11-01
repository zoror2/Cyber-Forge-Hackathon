# JSON and YAML connector configs

**Add source → Paste a config** accepts JSON or YAML in the same text box.
You can also upload a `.json`, `.yaml` or `.yml` file, up to 256 KiB.

1. Paste or upload the config.
2. Press **Check config**. The server converts the data to the engine's canonical
   JSON representation and applies the existing config/security validator.
3. Review the endpoint, mapping and required credentials.
4. Press **Connect** to save, preview, activate and collect.
5. Open **OCSF records** to inspect the collected data.

Conversion is deterministic and does not call an LLM. Configs remain versioned
engine instructions. The collected records are mapped into OCSF and stored in
PostgreSQL. The same JSON/YAML config has the same normalized hash, so uploading
it again does not create a duplicate revision. Editing the text invalidates the
previously checked draft; it must be checked again before connecting.

Use [mock_users.yaml](../configs/mock_users.yaml) for a complete YAML example.
It describes the same source as [mock_users.json](../configs/mock_users.json).
Both examples use the existing local Docker mock vendor and collect 25 users
across three pages. Change the source ID when creating a separate demonstration.

## API

- `POST /configs/check`: convert and validate without saving or fetching.
- `POST /configs`: convert, validate and save a normalized revision.
- Send raw YAML with `Content-Type: application/yaml` or `text/yaml`.
- `text/plain` auto-detects JSON/YAML, as used by the paste/upload interface.
- Explicit `application/json` requests retain strict JSON parsing.

Both formats use exactly the same connector fields (`request`, `auth`,
`pagination`, `destination.mapping`, and so on). YAML support changes the file
format; it does not infer another tool's schema or unsupported vendor features.
Quote string-valued query parameters and headers, for example
`params: {per_page: "100"}`. Mapping entries use the existing `{path: ...}`
field objects, rather than a new shorthand syntax.
Use secret references instead of credential values. Secrets, destination checks,
tenant ownership, limits and execution approval rules are unchanged.

## YAML rules

- One mapping document; unique string keys; at most 30 nested levels.
- No anchors, aliases, merge keys, custom tags or binary values.
- Decimal integers preserve large-ID precision. Finite JSON-compatible floats
  are accepted, including bounded scientific notation; exact integral values
  normalize without rounding. Ambiguous octal/hex spellings and non-finite
  numbers are rejected. Quote IDs when leading zeroes are significant.
- Date scalar text remains text; configured datetime transformations determine
  its meaning. Parsing YAML does not silently assign a timezone.
- Unknown fields and unsafe settings fail the shared validator. Error messages
  do not echo raw input values.

## Verification

- Parser tests cover JSON/YAML equivalence, comments, block/flow style, duplicate
  keys, multiple documents, aliases/tags, size/depth, large IDs and dates.
- Docker API tests cover normalized JSON review, no save on check, equivalent
  config hashes, preview without storage, collection/upsert, tenant isolation,
  no AI usage, strict JSON headers and unsafe YAML rejection.
- Headless Edge exercises pasted YAML, uploaded YAML, uploaded JSON, actual
  collection into OCSF, stale-review invalidation and duplicate-key feedback.
- Browser command: `node scripts/check-config-formats.cjs` against the prepared
  localhost demo. Results: `data/yaml-browser-check.log`.
