from celery import Celery

from app.settings import get_settings

settings = get_settings()


def _resolve_backend() -> str:
    if settings.celery_result_backend:
        return settings.celery_result_backend
    return settings.redis_url


celery_app = Celery(
    "cloudarena",
    broker=settings.redis_url,
    backend=_resolve_backend(),
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_default_queue="default",
    broker_connection_retry_on_startup=True,
)
