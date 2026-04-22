"""TrapEvent storage -- SQLite-backed event persistence."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from oubliette.models import TrapEvent


class EventStore:
    """SQLite store for trap events."""

    def __init__(self, db_path: str = "data/oubliette.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    arguments TEXT NOT NULL,
                    response_sent TEXT NOT NULL,
                    deception_profile TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    breadcrumbs_followed TEXT NOT NULL,
                    probes_triggered TEXT NOT NULL,
                    mitre_atlas_mapping TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_session ON events(session_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON events(source_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")

    def save(self, event: TrapEvent) -> None:
        d = event.to_dict()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO events
                   (event_id, timestamp, session_id, source_ip, tool_name,
                    arguments, response_sent, deception_profile, fingerprint,
                    breadcrumbs_followed, probes_triggered, mitre_atlas_mapping)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    d["event_id"],
                    d["timestamp"],
                    d["session_id"],
                    d["source_ip"],
                    d["tool_name"],
                    json.dumps(d["arguments"]),
                    json.dumps(d["response_sent"]),
                    d["deception_profile"],
                    json.dumps(d["fingerprint"]),
                    json.dumps(d["breadcrumbs_followed"]),
                    json.dumps(d["probes_triggered"]),
                    json.dumps(d["mitre_atlas_mapping"]),
                ),
            )

    def get_by_session(self, session_id: str) -> list[dict]:
        return self._query(
            "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp", (session_id,)
        )

    def get_by_source_ip(self, source_ip: str) -> list[dict]:
        return self._query(
            "SELECT * FROM events WHERE source_ip = ? ORDER BY timestamp", (source_ip,)
        )

    def get_all(self, limit: int = 100) -> list[dict]:
        return self._query("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))

    def count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
            return row[0]

    def _query(self, sql: str, params: tuple = ()) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()
            results = []
            for row in rows:
                d = dict(row)
                for key in (
                    "arguments",
                    "response_sent",
                    "fingerprint",
                    "breadcrumbs_followed",
                    "probes_triggered",
                    "mitre_atlas_mapping",
                ):
                    if key in d and isinstance(d[key], str):
                        d[key] = json.loads(d[key])
                results.append(d)
            return results
