import json
from datetime import datetime

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    from app.main import app
    from app.adapters import sdk as sdk_module
    from app.adapters import stratus as stratus_module
    from app.store import insert_event
    from app.workers import tasks as tasks_module
    from app.routes import events as events_routes
    from app.routes import runs as runs_routes
    from app.routes import reports as reports_routes
    from app.routes import facts as facts_routes

    def fake_run_sdk(technique_id: str, adapter: str, params):
        return {"ok": True, "findings": [f"finding-for-{technique_id}"]}

    def fake_run_stratus(technique_id: str, adapter: str, params, timeout=None):
        return {"ok": True, "stdout": "stratus ok"}

    def fake_post_event(
        run_id,
        event_type,
        payload,
        *,
        phase=None,
        severity=None,
        resource=None,
        artifacts=None,
        summary=None,
        details=None,
    ):
        payload_with_type = dict(payload)
        payload_with_type.setdefault("event_type", event_type)
        status = payload_with_type.get("status") or phase
        artifacts_json = json.dumps(artifacts) if artifacts else None
        insert_event(
            run_id=run_id,
            ts=datetime.utcnow().isoformat(),
            technique_id=payload_with_type.get("technique_id"),
            phase=phase,
            status=status,
            severity=severity,
            resource=resource,
            artifacts_json=artifacts_json,
            payload=payload_with_type,
            summary=summary,
            details_json=json.dumps(details) if details else None,
        )

    async def fake_require_auth(credentials=None):
        return {"sub": "test-user"}

    monkeypatch.setattr(sdk_module, "run_sdk", fake_run_sdk)
    monkeypatch.setattr(stratus_module, "run_stratus", fake_run_stratus)
    monkeypatch.setattr(tasks_module, "_post_event", fake_post_event)

    from app import auth as auth_module
    app.dependency_overrides[auth_module.require_auth] = lambda: {"sub": "test-user"}
    app.dependency_overrides[events_routes.require_auth] = lambda: {"sub": "test-user"}
    app.dependency_overrides[runs_routes.require_auth] = lambda: {"sub": "test-user"}
    app.dependency_overrides[reports_routes.require_auth] = lambda: {"sub": "test-user"}
    app.dependency_overrides[facts_routes.require_auth] = lambda: {"sub": "test-user"}

    test_client = TestClient(app)
    try:
        yield test_client
    finally:
        app.dependency_overrides.clear()


def test_run_flow_creates_events_and_report(client):
    goals = "integration-test"
    response = client.post(
        "/runs",
        headers={"Authorization": "Bearer test"},
        json={"goals": goals},
    )
    assert response.status_code == 200
    data = response.json()
    run_id = data["run_id"]

    events_response = client.get(f"/events/{run_id}", headers={"Authorization": "Bearer test"})
    assert events_response.status_code == 200
    events = events_response.json()["events"]
    assert len(events) >= 2
    assert any(event.get("summary") for event in events)

    report_response = client.post(
        f"/reports/{run_id}",
        headers={"Authorization": "Bearer test"},
        json={},
    )
    assert report_response.status_code == 200
    markdown = report_response.json()["markdown"]
    assert "T-S3-001" in markdown or "T-S3-PUBLIC-POLICY" in markdown
    assert "Remediation" in markdown
