import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.store import init_db


@pytest.fixture(autouse=True)
def configure_test_env(monkeypatch, tmp_path):
    db_path = tmp_path / "test_cloudarena.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    init_db(f"sqlite:///{db_path}")
    yield
    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def facts_builder():
    def _builder(public_buckets=None, services=None):
        public_buckets = public_buckets or []
        services = services or {}
        s3_entries = [{"name": name, "public": public} for name, public in public_buckets]
        return {
            "account": "123456789012",
            "region": "us-east-1",
            "services": {"s3": s3_entries, **services},
        }

    return _builder
