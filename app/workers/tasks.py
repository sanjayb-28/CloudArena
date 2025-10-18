import logging
from typing import Any, Dict, List

import httpx

from app.settings import get_settings
from .celery_app import celery_app

logger = logging.getLogger(__name__)


def _post_event(run_id: str, event_type: str, payload: Dict[str, Any]) -> None:
    settings = get_settings()
    url = settings.api_base_url.rstrip("/") + "/events"

    headers = {"Content-Type": "application/json"}
    if settings.auth_token:
        headers["Authorization"] = f"Bearer {settings.auth_token}"

    event_body = {"run_id": run_id, "event_type": event_type, "payload": payload}

    with httpx.Client(timeout=10.0) as client:
        response = client.post(url, json=event_body, headers=headers)
        response.raise_for_status()


@celery_app.task(name="cloudarena.health.ping")
def ping() -> str:
    return "pong"


@celery_app.task(name="cloudarena.run.execute_runbook")
def execute_runbook(run_id: str, runbook: Dict[str, Any]) -> str:
    steps: List[Dict[str, Any]] = runbook.get("steps", [])

    for index, step in enumerate(steps, start=1):
        step_payload = {
            "index": index,
            "technique_id": step.get("technique_id"),
            "params": step.get("params", {}),
        }

        try:
            _post_event(run_id, "run.step", {**step_payload, "status": "queued"})
            _post_event(run_id, "run.step", {**step_payload, "status": "ok"})
        except httpx.HTTPError as exc:
            logger.error("Failed to emit event for run %s step %s: %s", run_id, step_payload.get("technique_id"), exc)
            try:
                _post_event(
                    run_id,
                    "run.step",
                    {**step_payload, "status": "error", "reason": str(exc)},
                )
            except httpx.HTTPError:
                logger.exception("Failed to send error event for run %s", run_id)
            raise

    try:
        _post_event(run_id, "run.completed", {"status": "ok", "step_count": len(steps)})
    except httpx.HTTPError as exc:
        logger.error("Failed to emit run completion event for %s: %s", run_id, exc)
        raise

    return "queued"
