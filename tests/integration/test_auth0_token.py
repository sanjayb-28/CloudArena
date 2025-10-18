import json

import pytest


@pytest.fixture
def mock_httpx(monkeypatch):
    responses = []
    state = {"payload": {}, "status_code": 200}

    class MockResponse:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError("HTTP error")

        def json(self):
            return self._payload

    class MockClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, data=None):
            call = {"url": url, "data": data}
            responses.append(call)
            return MockResponse(state["status_code"], state["payload"])

    monkeypatch.setattr("app.workers.tasks.httpx.Client", MockClient)

    class Context:
        def set(self, payload, status_code=200):
            state["payload"] = payload
            state["status_code"] = status_code

    return Context(), responses


def test_auth0_m2m_token_success(monkeypatch, mock_httpx):
    context, responses = mock_httpx
    context.set({"access_token": "m2m-token", "expires_in": 3600})

    monkeypatch.setenv("AUTH0_M2M_CLIENT_ID", "client")
    monkeypatch.setenv("AUTH0_M2M_CLIENT_SECRET", "secret")
    monkeypatch.setenv("AUTH0_M2M_AUDIENCE", "https://audience")
    monkeypatch.setenv("AUTH0_DOMAIN", "example.auth0.com")

    from app.workers.tasks import get_bearer_token, _token_cache

    _token_cache.clear()
    token = get_bearer_token()

    assert token == "m2m-token"
    assert responses[0]["data"]["client_id"] == "client"


def test_auth0_m2m_token_fallback(monkeypatch, mock_httpx):
    context, responses = mock_httpx
    context.set({}, status_code=500)

    monkeypatch.setenv("AUTH0_M2M_CLIENT_ID", "client")
    monkeypatch.setenv("AUTH0_M2M_CLIENT_SECRET", "secret")
    monkeypatch.setenv("AUTH0_M2M_AUDIENCE", "https://audience")
    monkeypatch.setenv("AUTH0_DOMAIN", "example.auth0.com")
    monkeypatch.setenv("AUTH_TOKEN", "static-token")

    from app.workers.tasks import get_bearer_token, _token_cache

    _token_cache.clear()
    token = get_bearer_token()

    assert token == "static-token"
