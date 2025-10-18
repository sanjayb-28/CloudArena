import os

import pytest


@pytest.fixture(autouse=True)
def configure_test_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./test_cloudarena.db")
    yield
    try:
        os.remove("test_cloudarena.db")
    except FileNotFoundError:
        pass
