import logging
from typing import Any, Dict

from celery import Celery

from app.settings import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


def _resolve_backend() -> str:
    if settings.celery_result_backend:
        return settings.celery_result_backend
    return settings.redis_url


celery_app = Celery(
    "cloudarena",
    broker=settings.redis_url,
    backend=_resolve_backend(),
)


@celery_app.task(name="cloudarena.health.ping")
def ping() -> str:
    return "pong"


@celery_app.task(name="cloudarena.run.execute_runbook")
def execute_runbook(run_id: str, runbook: Dict[str, Any]) -> str:
    logger.info("Stub execute_runbook invoked for run %s with %d steps.", run_id, len(runbook.get("steps", [])))
    return "queued"
