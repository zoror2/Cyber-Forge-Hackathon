"""SQLite persistence with stable-key upserts and field-level quarantine."""

import json
import sqlite3
from pathlib import Path

from .schemas import EventRecord


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS records (
                    entity_type TEXT NOT NULL, source TEXT NOT NULL, external_id TEXT NOT NULL,
                    payload TEXT NOT NULL, fetched_at TEXT NOT NULL,
                    UNIQUE(source, entity_type, external_id)
                );
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY, source TEXT NOT NULL, record_index INTEGER NOT NULL,
                    reason TEXT NOT NULL
                );
            """)

    def _connect(self):
        return sqlite3.connect(self.path, timeout=5)

    def upsert(self, record: EventRecord):
        payload = record.model_dump(mode="json")
        with self._connect() as db:
            db.execute("""INSERT INTO records(entity_type,source,external_id,payload,fetched_at)
                VALUES(?,?,?,?,?) ON CONFLICT(source,entity_type,external_id) DO UPDATE SET
                payload=excluded.payload,fetched_at=excluded.fetched_at""",
                ("event", record.source, record.id, json.dumps(payload), payload["fetched_at"]))

    def quarantine(self, source: str, index: int, reason: str):
        with self._connect() as db:
            db.execute("INSERT INTO quarantine(source,record_index,reason) VALUES(?,?,?)", (source, index, reason))

    def counts(self):
        with self._connect() as db:
            return {"records": db.execute("SELECT COUNT(*) FROM records").fetchone()[0],
                    "quarantined": db.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0]}

