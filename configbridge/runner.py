"""Connects config, HTTP, mapping, validation and SQLite into one run."""

from datetime import datetime, timezone

from .http_client import fetch_json
from .mapping import get_items, map_record
from .store import Store


def run_config(config, store: Store, client=None):
    payload = fetch_json(config, client)
    items = get_items(payload, config.response.items_path)
    fetched_at = datetime.now(timezone.utc)
    accepted = quarantined = 0
    for index, item in enumerate(items):
        try:
            record = map_record(item, config, fetched_at)
            store.upsert(record)
            accepted += 1
        except ValueError as exc:
            store.quarantine(config.id, index, str(exc))
            quarantined += 1
    return {"source": config.id, "received": len(items), "accepted": accepted,
            "quarantined": quarantined, "outcome": "completed_with_errors" if quarantined else "success",
            **store.counts()}

