import json

import pytest

from app.reporter import render_report


@pytest.fixture
def facts_builder():
    def build(public=False):
        return {
            "account": "123456789012",
            "region": "us-east-1",
            "services": {
                "s3": [{"name": "bucket", "public": public}],
            },
        }

    return build


@pytest.fixture
def events_builder():
    def build():
        return [
            {
                "payload": {
                    "event_type": "run.step",
                    "index": 1,
                    "technique_id": "T-EC2-SG-OPEN",
                    "status": "ok",
                },
                "severity": "high",
                "summary": "1 security group allows 0.0.0.0/0",
                "details": {
                    "findings": [
                        {
                            "resource": "sg-123",
                            "issue": "Ingress from 0.0.0.0/0",
                            "severity": "high",
                        }
                    ]
                },
            },
            {
                "payload": {"event_type": "run.completed", "status": "ok", "step_count": 1},
                "severity": "low",
            },
        ]

    return build


def test_reporter_gemini_success(monkeypatch, facts_builder, events_builder):
    calls = []

    import types
    import sys

    fake_module = types.SimpleNamespace()
    
    class FakeModel:
        def generate_content(self, prompt):
            calls.append(prompt)

            class Response:
                text = "Gemini summary"

            return Response()

    def fake_configure(api_key):
        calls.append("configure")

    fake_module.configure = fake_configure
    fake_module.GenerativeModel = lambda name: FakeModel()

    google_pkg = types.SimpleNamespace(generativeai=fake_module)
    sys.modules["google"] = google_pkg
    sys.modules["google.generativeai"] = fake_module

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr("app.reporter.reporter.get_settings", lambda: type("S", (), {"gemini_api_key": "test-key", "env": "dev"})())

    markdown = render_report(facts_builder(public=True), events_builder())

    assert "Gemini summary" in markdown
    assert calls


def test_reporter_gemini_fallback(monkeypatch, facts_builder, events_builder):
    import types
    import sys

    fake_module = types.SimpleNamespace()

    def fake_configure(api_key):
        raise RuntimeError("config error")

    fake_module.configure = fake_configure
    fake_module.GenerativeModel = lambda name: None

    google_pkg = types.SimpleNamespace(generativeai=fake_module)
    sys.modules["google"] = google_pkg
    sys.modules["google.generativeai"] = fake_module

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr("app.reporter.reporter.get_settings", lambda: type("S", (), {"gemini_api_key": "test-key", "env": "dev"})())

    markdown = render_report(facts_builder(public=True), events_builder())

    assert "Gemini summary" not in markdown
    assert "Findings" in markdown
