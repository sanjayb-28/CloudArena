from datetime import datetime

from app.store import init_db, insert_event, list_events


def test_store_insert_and_list_events(tmp_path):
    db_path = tmp_path / "store.db"
    init_db(f"sqlite:///{db_path}")

    insert_event(
        run_id="run-1",
        ts=datetime.utcnow().isoformat(),
        technique_id="T-TEST",
        phase="queued",
        status="queued",
        severity="low",
        resource="resource-1",
        artifacts_json="[]",
        payload={"status": "queued"},
    )

    events = list_events("run-1")

    assert len(events) == 1
    record = events[0]
    assert record["run_id"] == "run-1"
    assert record["technique_id"] == "T-TEST"
    assert record["phase"] == "queued"
    assert record["status"] == "queued"
    assert record["severity"] == "low"
    assert record["resource"] == "resource-1"
