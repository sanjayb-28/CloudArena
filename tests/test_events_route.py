import pytest

fastapi = pytest.importorskip("fastapi")

from fastapi import status  # type: ignore
from fastapi.testclient import TestClient  # type: ignore

from app.main import app


client = TestClient(app)


def test_get_events_returns_empty_list_when_no_events(monkeypatch):
    run_id = "non-existent-run"

    response = client.get(
        f"/events/{run_id}",
        headers={"Authorization": "Bearer changeme-internal-token"},
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"events": []}
