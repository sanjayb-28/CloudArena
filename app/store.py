import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

Connection = sqlite3.Connection

_DB_PATH: Optional[Path] = None


def _ensure_schema(conn: Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            goals TEXT,
            runbook_json TEXT NOT NULL,
            facts_json TEXT,
            status TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT
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
            summary TEXT,
            details_json TEXT,
            FOREIGN KEY(run_id) REFERENCES runs(run_id)
        );
        """
    )
    try:
        conn.execute("ALTER TABLE runs ADD COLUMN facts_json TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE runs ADD COLUMN status TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE runs ADD COLUMN completed_at TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE events ADD COLUMN summary TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE events ADD COLUMN details_json TEXT")
    except sqlite3.OperationalError:
        pass
    conn.commit()


def _resolve_sqlite_path(database_url: str) -> Path:
    if database_url.startswith("sqlite:////"):
        path_str = database_url.replace("sqlite:////", "/", 1)
    elif database_url.startswith("sqlite:///"):
        path_str = database_url.replace("sqlite:///", "", 1)
    else:
        raise ValueError(f"Unsupported database URL '{database_url}'")

    path = Path(path_str)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def init_db(database_url: str) -> None:
    """Initialize the SQLite database at the provided URL."""

    global _DB_PATH
    path = _resolve_sqlite_path(database_url)

    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()

    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        _ensure_schema(conn)

    _DB_PATH = path


@contextmanager
def _connect() -> Generator[Connection, None, None]:
    if _DB_PATH is None:
        raise RuntimeError("Database not initialized. Call init_db first.")
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def insert_run(
    run_id: str,
    goals: Optional[str],
    runbook_json: str,
    facts_json: Optional[str],
    status: Optional[str],
) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO runs(run_id, goals, runbook_json, facts_json, status, created_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                goals=excluded.goals,
                runbook_json=excluded.runbook_json,
                facts_json=excluded.facts_json,
                status=excluded.status,
                created_at=excluded.created_at,
                completed_at=excluded.completed_at;
            """,
            (run_id, goals, runbook_json, facts_json, status, datetime.utcnow().isoformat(), None),
        )
        conn.commit()


def get_run(run_id: str) -> Optional[Dict[str, Any]]:
    with _connect() as conn:
        cursor = conn.execute(
            "SELECT run_id, goals, runbook_json, facts_json, status, created_at, completed_at FROM runs WHERE run_id = ?",
            (run_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return _hydrate_run(dict(row))


def list_runs(limit: int = 20) -> List[Dict[str, Any]]:
    with _connect() as conn:
        cursor = conn.execute(
            """
            SELECT run_id, goals, runbook_json, facts_json, status, created_at, completed_at
            FROM runs
            ORDER BY datetime(created_at) DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [_hydrate_run(dict(row)) for row in cursor.fetchall()]


def delete_all_runs() -> None:
    """Remove all run and event records from the local store."""

    with _connect() as conn:
        conn.execute("DELETE FROM events;")
        conn.execute("DELETE FROM runs;")
        conn.commit()


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
    summary: Optional[str] = None,
    details_json: Optional[str] = None,
) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO events(
                run_id, ts, technique_id, phase, status, severity, resource, artifacts_json, payload_json, summary, details_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                summary,
                details_json,
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
                payload_json,
                summary,
                details_json
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
            if item.get("details_json"):
                try:
                    item["details"] = json.loads(item.pop("details_json"))
                except json.JSONDecodeError:
                    item["details"] = {}
            else:
                item["details"] = {}
            item["summary"] = item.pop("summary", None)
            items.append(item)
        return items


def update_run_status(
    run_id: str,
    status: Optional[str],
    *,
    completed_at: Optional[datetime] = None,
) -> None:
    with _connect() as conn:
        if completed_at is not None:
            completed_value = (
                completed_at.isoformat() if isinstance(completed_at, datetime) else str(completed_at)
            )
            conn.execute(
                "UPDATE runs SET status = ?, completed_at = ? WHERE run_id = ?",
                (status, completed_value, run_id),
            )
        else:
            conn.execute(
                "UPDATE runs SET status = ? WHERE run_id = ?",
                (status, run_id),
            )
        conn.commit()


def _hydrate_run(record: Dict[str, Any]) -> Dict[str, Any]:
    hydrated = dict(record)
    runbook_json = hydrated.get("runbook_json")
    if isinstance(runbook_json, str):
        try:
            hydrated["runbook"] = json.loads(runbook_json)
        except json.JSONDecodeError:
            hydrated["runbook"] = None
    else:
        hydrated["runbook"] = None

    facts_json = hydrated.get("facts_json")
    if isinstance(facts_json, str):
        try:
            hydrated["facts"] = json.loads(facts_json)
        except json.JSONDecodeError:
            hydrated["facts"] = None
    else:
        hydrated["facts"] = None
    return hydrated
