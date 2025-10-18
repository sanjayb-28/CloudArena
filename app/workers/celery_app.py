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
)


@celery_app.task(name="cloudarena.health.ping")
def ping() -> str:
    return "pong"
