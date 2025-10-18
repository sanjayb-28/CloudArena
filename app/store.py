import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

Connection = sqlite3.Connection

_DB_PATH: Optional[Path] = None


def _ensure_schema(conn: Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            goals TEXT,
            runbook_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            technique_id TEXT,
            phase TEXT,
            status TEXT,
            severity TEXT,
            resource TEXT,
            artifacts_json TEXT,
            payload_json TEXT,
            FOREIGN KEY(run_id) REFERENCES runs(run_id)
        );
        """
    )
    conn.commit()


def init_db(database_url: str) -> None:
    """Initialize the SQLite database at the provided URL."""

    global _DB_PATH
    if database_url.startswith("sqlite:///"):
        path = Path(database_url.replace("sqlite:///", "", 1)).resolve()
    else:
        raise ValueError(f"Unsupported database URL '{database_url}'")

    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        _ensure_schema(conn)

    _DB_PATH = path


@contextmanager
def _connect() -> Connection:
    if _DB_PATH is None:
        raise RuntimeError("Database not initialized. Call init_db first.")
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def insert_run(run_id: str, goals: Optional[str], runbook_json: str) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO runs(run_id, goals, runbook_json, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                goals=excluded.goals,
                runbook_json=excluded.runbook_json,
                created_at=excluded.created_at;
            """,
            (run_id, goals, runbook_json, datetime.utcnow().isoformat()),
        )
        conn.commit()


def get_run(run_id: str) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        cursor = conn.execute(
            "SELECT run_id, goals, runbook_json, created_at FROM runs WHERE run_id = ?",
            (run_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)


def list_runs(limit: int = 20) -> List[Dict[str, Any]]:
    with _connect() as conn:
        cursor = conn.execute(
            """
            SELECT run_id, goals, runbook_json, created_at
            FROM runs
            ORDER BY datetime(created_at) DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]


def insert_event(
    run_id: str,
    ts: str,
    technique_id: Optional[str],
    phase: Optional[str],
    status: Optional[str],
    severity: Optional[str],
    resource: Optional[str],
    artifacts_json: Optional[str],
    payload: Dict[str, Any],
) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO events(
                run_id, ts, technique_id, phase, status, severity, resource, artifacts_json, payload_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                run_id,
                ts,
                technique_id,
                phase,
                status,
                severity,
                resource,
                artifacts_json,
                json.dumps(payload) if payload else None,
            ),
        )
        conn.commit()


def list_events(run_id: str) -> List[Dict[str, Any]]:
    with _connect() as conn:
        cursor = conn.execute(
            """
            SELECT
                run_id,
                ts,
                technique_id,
                phase,
                status,
                severity,
                resource,
                artifacts_json,
                payload_json
            FROM events
            WHERE run_id = ?
            ORDER BY id ASC;
            """,
            (run_id,),
        )
        items = []
        for row in cursor.fetchall():
            item = dict(row)
            if item.get("artifacts_json"):
                try:
                    item["artifacts"] = json.loads(item.pop("artifacts_json"))
                except json.JSONDecodeError:
                    item["artifacts"] = []
            else:
                item["artifacts"] = []
            if item.get("payload_json"):
                try:
                    item["payload"] = json.loads(item.pop("payload_json"))
                except json.JSONDecodeError:
                    item["payload"] = {}
            else:
                item["payload"] = {}
            items.append(item)
        return items
