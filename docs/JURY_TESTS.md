# Jury-style engine verification

1 November 2026. The organisers have not supplied a config schema or sample, so
these checks use the engine's current strict JSON contract. They do not establish
compatibility with an arbitrary YAML/JSON format or unsupported API workflow.
AI and commercial-vendor accounts are absent from the new test.

## New black-box scenario

`tests/jury_test.go` reads independent config, source and expected-result files
from `tests/testdata/jury/`, then exercises the real HTTPS engine, API, mapper and
Docker PostgreSQL. The Go test/API process runs on Windows; the whole app image
is not being claimed as Docker-tested here.

The scenario checks:

- An externally supplied supported config can be saved, previewed, activated
  and run. The API still takes tenant identity from authentication.
- Nested record extraction and three-page collection produce exactly four
  received records: two stored and two quarantined per run.
- Numeric ID `9007199254740993` retains every digit instead of rounding through
  floating-point conversion.
- Whitespace trimming, boolean-to-enum mapping and optional null values produce
  the expected fields.
- `2026-11-01T10:00:00+05:30` maps to epoch milliseconds `1793507400000`.
- Missing identity and malformed dates are quarantined without losing good rows.
- Repeating the run leaves exactly two stored records, with four quarantine
  entries across the two runs. Preview writes neither records nor run history.
- Another tenant cannot read the connector's records.
- Eleven invalid inputs return validation errors before any vendor request:
  unsupported POST, HTTP, inline credentials, missing identity mapping,
  unsupported class, unsupported paging, negative page size, malformed pointer,
  tenant injection, duplicate JSON key and trailing JSON. Validation does not
  echo the synthetic credential or persist a config.

Expected record values are checked against `expected_users.json`; checking only
that the HTTP request succeeded would not establish correct collection.

## Existing tests included in the full gate

The engine/pagination suites also test API key, Bearer, Basic and OAuth,
host/port binding, tenant-separated tokens, wrong credentials, no secret logging,
network and server failures, bounded backoff, Retry-After, response limits,
malformed JSON, incorrect collection paths, empty/short/full pages, repeating
cursors/links, pagination bounds and preservation of earlier valid pages when a
later page fails.

Integration tests cover all five OCSF classes, record conversions, quarantine,
upserts, preview/checkpoint safety, scheduling, overlap locks, run recovery,
health, IAM, notifications, SIEM and tenant isolation. A passing suite is evidence
for these cases; it cannot prove that every possible input has no defects.

`pkg/config/fuzz_test.go` additionally mutates untrusted config inputs to look for
parser/validator crashes. A short fuzz run complements the named cases; it is not
an exhaustive proof.

## Reproduce

```powershell
# Set TEST_DATABASE_URL to a disposable Docker PostgreSQL admin database.
go test -v -count=1 ./tests -run '^TestJuryProvidedConfigsAndExactStoredResults$'
go test ./pkg/config -run '^$' -fuzz '^FuzzDecodeUntrustedConfig$' -fuzztime=10s -parallel=2
# With TEST_OPENSEARCH_URL also set to the local test service:
. ./scripts/check.ps1
```

Evidence is local and ignored: `data/jury-config-proof.log`,
`data/jury-parser-fuzz.log` and `data/jury-full-gate.log`.
No organiser config or commercial-vendor live test is claimed by this report.

## Result

All new supplied-config scenarios passed. The short parser fuzz run completed
38,435 executions with no crash found. The full gate passed formatting, vet,
race detection, all ordinary tests using real Docker PostgreSQL/OpenSearch and
all six native command builds; the integration package took 115.573 seconds.
No production-engine code change was needed during this jury-test round.
Changes remain local; this round did not push or merge remotely.
