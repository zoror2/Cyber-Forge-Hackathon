"""End-to-end acceptance checks for the Milestone 1 flow."""

from pathlib import Path
import httpx

from configbridge.config import load_config
from configbridge.runner import run_config
from configbridge.store import Store

ROOT = Path(__file__).resolve().parents[1]


def test_fixture_maps_quarantines_and_upserts(tmp_path):
    config = load_config(ROOT / "configs" / "fixture_events.yaml")
    body = (ROOT / "tests" / "fixtures" / "events.json").read_bytes()
    client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, content=body, request=request)))
    store = Store(tmp_path / "demo.sqlite3")
    try:
        first = run_config(config, store, client)
        second = run_config(config, store, client)
    finally:
        client.close()
    assert (first["received"], first["accepted"], first["quarantined"]) == (4, 3, 1)
    assert (second["records"], second["quarantined"]) == (3, 2)
    with store._connect() as db:
        reason = db.execute("SELECT reason FROM quarantine LIMIT 1").fetchone()[0]
        row = db.execute("SELECT payload FROM records ORDER BY external_id LIMIT 1").fetchone()[0]
    assert "required field is missing" in reason
    assert '"timestamp_precision": "date"' in row

