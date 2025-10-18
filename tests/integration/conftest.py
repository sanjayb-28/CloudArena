import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.settings import get_settings
from app.store import init_db
from app.workers.celery_app import celery_app


@pytest.fixture(autouse=True)
def integration_env(monkeypatch, tmp_path):
    db_path = tmp_path / "integration.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("CELERY_TASK_ALWAYS_EAGER", "1")
    monkeypatch.setenv("API_BASE_URL", "http://testserver")

    get_settings.cache_clear()
    settings = get_settings()

    init_db(settings.database_url)
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True

    yield

    celery_app.conf.task_always_eager = False
    celery_app.conf.task_eager_propagates = False
    get_settings.cache_clear()
