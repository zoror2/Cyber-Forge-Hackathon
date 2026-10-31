# ConfigBridge

ConfigBridge is a small, configuration-driven engine for collecting security data from JSON APIs. Milestones 0 and 1 implement one GET request, configurable field mapping, common Event validation, SQLite upsert, quarantine, and a concise run summary. This is the first local slice; it does not yet implement provider authentication, pagination, retry policy, scheduling, or a health page.

## Run on Windows

Install Python 3.11 or 3.12, then from PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m configbridge.cli validate configs\fixture_events.yaml
python -m configbridge.cli run configs\fixture_events.yaml --fixture tests\fixtures\events.json --db data\demo.sqlite3
```

Run the last command a second time. The database keeps three unique records; each run records the one malformed row in quarantine. To run checks: `python -m pytest`.

For a live public-feed attempt, use `python -m configbridge.cli run configs\cisa_kev.yaml`. That config is not yet included because live endpoint access has not been verified in this environment. Never put a token in YAML; secret-backed authentication is a later milestone.

## One run, in plain language

`cli.py` reads the YAML through `config.py`. `runner.py` asks `http_client.py` for JSON, finds the configured array and calls `mapping.py` for each row. Valid common Event records go to `store.py`; a bad row gets a short reason in quarantine while the rest continue. The CLI prints counts. SQLite identifies records by source, entity type, and external ID, so a rerun updates the same rows.

## Current milestone checklist

- [x] Milestone 0: package setup, dependency pins, ignore rules, environment placeholder, sample config and tests (files created; install not run).
- [x] Milestone 1 implementation: YAML validation, injectable JSON HTTP, nested mapping/date conversion, Event validation, SQLite upsert, quarantine and summary (execution awaits Python availability).
- [ ] Milestone 1 live CISA verification: not attempted; Python is not installed in the provided environment, and outbound access is not confirmed.

## Requirement traceability

These links describe the planned organizer requirements. Items beyond Milestone 1 are explicitly pending.

| ID | Status | Code and evidence |
|---|---|---|
| FR-1 | Pending | Authentication is outside Milestones 0â€“1. |
| FR-2 | Partial | URL, GET method, and parameters: [schemas.py](configbridge/schemas.py), [http_client.py](configbridge/http_client.py). |
| FR-3 | Pending | Pagination is outside Milestones 0â€“1. |
| FR-4 | Pending | Scheduling is outside Milestones 0â€“1. |
| FR-5 | Partial | Nested paths and string/integer/date/lookup transforms: [mapping.py](configbridge/mapping.py). |
| FR-6 | Pending | Secret resolution/redaction is outside Milestones 0â€“1. |
| FR-7 | Pending | Retry handling is outside Milestones 0â€“1. |
| FR-8 | Pending | 429 handling is outside Milestones 0â€“1. |
| FR-9 | Partial | Invalid rows are quarantined: [runner.py](configbridge/runner.py), [store.py](configbridge/store.py), [test_milestone1.py](tests/test_milestone1.py). |
| FR-10 | Pending | Health reporting is outside Milestones 0â€“1. |
| FR-11 | Partial | Common Event rows are validated and upserted in SQLite: [schemas.py](configbridge/schemas.py), [store.py](configbridge/store.py). |

## File guide

- `configbridge/schemas.py`: says which config and Event fields are valid.
- `configbridge/config.py`: safely reads YAML, rejects duplicate keys, and validates it.
- `configbridge/http_client.py`: fetches one JSON response through an injectable client.
- `configbridge/mapping.py`: finds nested values, converts dates, and validates Events.
- `configbridge/store.py`: saves records without duplicates and records quarantine reasons.
- `configbridge/runner.py`: connects fetch, mapping, validation and storage.
- `configbridge/cli.py`: provides the `validate` and `run` commands.
- `configs/fixture_events.yaml`: describes the offline demonstration connection.
- `tests/fixtures/events.json`: has three valid rows and one row missing its ID.
- `tests/test_milestone1.py`: checks the flow and repeat-run uniqueness.
- `pyproject.toml`: declares Python and the tested dependency versions for installation.
- `.env.example`: documents the future environment-variable convention without containing a secret.
- `PRD.md`: the product and challenge requirements.

