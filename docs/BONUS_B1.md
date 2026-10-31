# B-1: Incremental sync

## Jury explanation

“The first pull downloads the existing users and saves a time bookmark. Suppose
we have 1,000 users. Later, one user changes and one joins. The next pull asks the
vendor for those two changed records instead of downloading all 1,001 users.
The changed user is updated by ID, and the new user is inserted.

We save the bookmark only after the complete run succeeds. If the network cuts
out, a page fails, or a row cannot be mapped, the bookmark stays where it was.
The next attempt replays that range. Upserts prevent duplicate records.”

This feature is separate from duplicate prevention: upserts alone still download
everything. Incremental sync adds a persisted filter boundary to reduce downloads.

## Local demo

Start the local PostgreSQL instance, apply migrations with `bin/bootstrap.exe`,
then start `bin/api.exe` and `bin/mockvendor.exe` with the private `.env` loaded
(README setup). The API and mock remain bound to localhost.

In the prepared Windows workspace, use these terminals from the project root.
If the portable PostgreSQL instance is stopped, start it first:

```powershell
.\.tools\postgres\bin\pg_ctl.exe -D data\postgres-test -l data\postgres-test.log -o "-h 127.0.0.1 -p 55432" start
```

Terminal 1 (TLS mock):

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\load-env.ps1
.\bin\mockvendor.exe
```

Terminal 2 (migration and API):

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\scripts\load-env.ps1 -Bootstrap
.\bin\bootstrap.exe
.\scripts\load-env.ps1
.\bin\api.exe
```

Terminal 3:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/smoke-incremental.ps1
```

Expected synthetic result:

| Step | Records downloaded | Unique users stored |
|---|---:|---:|
| First pull | 3 | 3 |
| Update user 2 and add user 4 | 2 | 4 |
| No further changes | 0 | 4 |

The script first previews the draft and checks that no checkpoint was written.
It uses a new connector ID for each demonstration and records safe counts in
`data/b1-demo-result.json`. It uses the generated development CA; TLS verification
stays enabled. Its POST calls change only the synthetic mock fixture. The
platform still sends read-only GET requests to vendors.

Inspect progress with the authenticated
`GET /connectors/{id}/sync-state` request. Run history also shows `incremental`:
the exact `since`/`until` bounds, previous boundary and `checkpoint_committed`.

## Config

See [mock_incremental_users.json](../configs/mock_incremental_users.json):

```json
"incremental": {
  "type": "time_window",
  "start_time": "2020-01-01T00:00:00Z",
  "since_param": "updated_since",
  "until_param": "updated_before",
  "updated_at_path": "updated_at",
  "overlap_seconds": 0,
  "safety_lag_seconds": 0
}
```

`start_time` is the initial backfill boundary. The platform fills both query
parameters with RFC3339 UTC values; they must not also appear in static params
or collide with pagination. The raw modification timestamp is checked separately
from the normalized mapping, so it need not be stored as an extra User field.
Omitting `incremental` preserves existing full-sync behavior.

## Safe window rules

- The vendor must document an **inclusive** lower filter (`updated >= since`),
  **exclusive** upper filter (`updated < until`), timezone-aware RFC3339 values
  and stable pagination over the filtered range. This first version supports
  none/page/offset pagination. Link/cursor recipes need a separately designed
  contract; they are refused here instead of guessing at their semantics.
- The upper boundary is platform time minus an optional safety lag, rounded down
  to a second. The saved boundary marks a fully collected time interval, not the
  largest timestamp that happened to appear in the response. This also works
  for a successful empty response.
- `overlap_seconds` replays a small part of the previous interval to accommodate
  limited late arrivals; stable IDs deduplicate it. Safety lag/overlap must be
  chosen from the vendor's documented consistency delay and clock behavior.
  They cannot protect against indefinitely late, backdated or omitted records.
- Invalid/missing modification timestamps go to metadata-only quarantine.
  Any quarantine prevents checkpoint advancement, including an ordinary mapping
  error. Fix the source/mapping and replay; quarantined data is never skipped by
  advancing a bookmark without a recovery path.
- A returned timestamp outside the requested interval fails the run with
  `incremental_filter_not_respected`. This catches common ignored/misconfigured
  filters but cannot prove the vendor returned every matching record.
- Partial pages can remain stored after failure. Retries start from the previous
  committed boundary and upsert those rows again safely.
- The final run status and checkpoint update share one PostgreSQL transaction.
  Failed finalization cannot publish a successful checkpoint. Existing run-state
  fencing prevents abandoned workers from advancing it later.
- The checkpoint is scoped to tenant + connector and the exact config hash. Any
  config revision with a different hash conservatively starts again at the
  configured initial boundary. This can cost a backfill but avoids reusing
  progress after changing an endpoint, credential reference, filter or mapping.
- A backwards platform clock never moves an existing boundary backwards. An
  empty interval performs no HTTP request. Preview/test requests never commit
  progress, production records, quarantine, history or schedule state.

This is a working generic engine capability tested with a controlled TLS source.
It is **not enabled on CISA KEV or GitHub members**: those configs do not document
the required modification-window contract. Do not treat KEV `dateAdded` as an
update timestamp. Mohit's remaining real-source integration/evidence is deferred
as requested. No new paid/free-tier account or public API call is needed for B-1's
local demonstration, and this feature makes no AI calls.

## Files in simple terms

| File | What it does |
|---|---|
| `pkg/config/incremental.go` | Rejects unsupported or conflicting filter settings before a request. |
| `pkg/incremental/window.go` | Calculates the time range, fills query params and checks modification dates. |
| `internal/runner/runner.go` | Loads the bookmark, collects/maps pages and commits progress only on clean success. |
| `internal/store/sync_state.go` | Reads progress from the tenant's PostgreSQL rows. |
| `internal/store/store.go` | Saves the final run and new bookmark atomically. |
| `004_incremental.sql` | Adds the time-window audit field to run history; existing checkpoints stay under RLS. |
| `internal/api/sync_state.go` | Lets an authenticated customer inspect their own progress. |
| `internal/mockvendor/incremental.go` | Supplies the local fake vendor and stable paginated snapshots. |
| `configs/mock_incremental_users.json` | Describes that source through config, without custom collector code. |
| `scripts/smoke-incremental.ps1` | Demonstrates 3, then 2, then 0 downloads and verifies four unique users. |
| `tests/incremental_test.go` | Exercises the combined HTTPS/API/PostgreSQL success, failure and recovery paths. |

## Verification scope

Focused tests cover initial backfill, changed-only requests, updates without
duplicates, empty responses/windows, restart persistence, tenant isolation,
quarantine, invalid dates, ignored filters, page/record caps, malformed JSON,
500 responses, cancellation, failed finalization, stale workers, config resets,
clock regression, overlap, preview and corrupt saved state. Unit tests cover
parameter security and exact inclusive/exclusive/timezone/nanosecond boundaries.
The mock's snapshot test checks that changing data between pages does not alter
an already-open snapshot.

Verified locally on 2026-10-31: the full formatting/vet/race/PostgreSQL gate and
all five Windows builds passed. All five Linux/amd64 static builds and Compose
configuration validation passed. The compiled B-1 demo produced 3 → 2 → 0
downloads with four unique users. Restarting the actual API process preserved
the bookmark and the next pull downloaded zero records. The existing full-sync
smoke still produced 25 unique users and accepted two/quarantined two malformed
fixture rows. These are controlled local results, not live-vendor or Docker
startup verification.

B-2/B-3 already exist. B-4 email alerts and B-5 browser onboarding were added in
the following step; see [BONUS_B4_B5.md](BONUS_B4_B5.md) for their demo and evidence.
