# Code walkthrough: Milestones 0â€“1

## Execution path

1. `cli.py` selects `validate` or `run` and loads the YAML.
2. `config.py` rejects oversized files and duplicate keys, then `schemas.py` checks the config shape.
3. `http_client.py` sends one GET using an injectable HTTPX client. Tests use a mock transport, so no network is needed.
4. `mapping.py` locates the response array, follows dotted/numeric paths, converts configured values, and validates each common Event.
5. `runner.py` stores each valid row and quarantines a bad row without stopping the other rows.
6. `store.py` uses SQLite's unique source/entity/ID key to update the same record on a repeated run.

## Explain it to judges

â€œA new source that fits the supported API shape is described in YAML. The same engine reads its record list, maps fields into our shared Event shape, and saves records by stable ID. A malformed row is kept out of the main records and gets a reason in quarantine. We use a local HTTP fixture to prove the flow without claiming a live API run.â€

Reproduce it with `python -m configbridge.cli run configs\fixture_events.yaml --fixture tests\fixtures\events.json --db data\demo.sqlite3` twice. Expected per-run counts: 4 received, 3 accepted, 1 quarantined; SQLite has 3 unique records afterward.

