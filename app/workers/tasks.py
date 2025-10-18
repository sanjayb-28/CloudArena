import logging
import signal
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.adapters.sdk import run_sdk
from app.adapters.stratus import run_stratus
from app.planner.planner import _load_techniques
from app.planner.schema import TechniqueSpec
from app.settings import get_settings
from .celery_app import celery_app

logger = logging.getLogger(__name__)

STEP_TIMEOUT_SECONDS = 120


class StepTimeoutError(Exception):
    """Raised when a runbook step exceeds the configured timeout."""


class StepExecutionError(Exception):
    """Raised when a technique reports an unsuccessful result."""

    def __init__(self, technique_id: Optional[str], result: Dict[str, Any]):
        self.result = result
        message = f"Technique {technique_id or 'unknown'} reported failure"
        super().__init__(message)


@contextmanager
def _step_timeout(seconds: int) -> None:
    def _handle_timeout(signum, frame):  # noqa: ARG001
        raise StepTimeoutError(f"Step execution timed out after {seconds} seconds.")

    previous = signal.signal(signal.SIGALRM, _handle_timeout)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _post_event(
    run_id: str,
    event_type: str,
    payload: Dict[str, Any],
    *,
    phase: Optional[str] = None,
    severity: Optional[str] = None,
    resource: Optional[str] = None,
    artifacts: Optional[List[Dict[str, Any]]] = None,
) -> None:
    settings = get_settings()
    url = settings.api_base_url.rstrip("/") + "/events"

    headers = {"Content-Type": "application/json"}
    if settings.auth_token:
        headers["Authorization"] = f"Bearer {settings.auth_token}"

    event_body: Dict[str, Any] = {
        "run_id": run_id,
        "event_type": event_type,
        "payload": payload,
    }
    if phase is not None:
        event_body["phase"] = phase
    if severity is not None:
        event_body["severity"] = severity
    if resource is not None:
        event_body["resource"] = resource
    if artifacts:
        event_body["artifacts"] = artifacts

    with httpx.Client(timeout=10.0) as client:
        response = client.post(url, json=event_body, headers=headers)
        response.raise_for_status()


def _write_stdout_artifact(run_id: str, step_index: int, content: str) -> str:
    base_path = Path("/tmp/cloudarena") / run_id
    base_path.mkdir(parents=True, exist_ok=True)
    artifact_path = base_path / f"step-{step_index}-stdout.log"
    artifact_path.write_text(content)
    return str(artifact_path)


def _cloudtrail_artifact_uri() -> Optional[str]:
    settings = get_settings()
    if settings.arena_account_id and settings.region:
        return f"s3://cloudtrail/AWSLogs/{settings.arena_account_id}/CloudTrail/{settings.region}/"
    return None


def _resolve_adapter(spec: Optional[TechniqueSpec]) -> Tuple[Optional[str], Optional[str]]:
    if not spec or not spec.impl:
        return None, None
    adapter_value = spec.impl.get("adapter")
    if not adapter_value or not isinstance(adapter_value, str):
        return None, None
    adapter_parts = adapter_value.split(".", 1)
    adapter_type = adapter_parts[0]
    adapter_identifier = adapter_value
    return adapter_type, adapter_identifier


def _run_step(
    adapter_type: Optional[str],
    adapter_identifier: Optional[str],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    if adapter_type == "stratus" and adapter_identifier:
        return run_stratus(adapter_identifier, adapter_type, params, timeout=STEP_TIMEOUT_SECONDS)
    if adapter_type == "sdk" and adapter_identifier:
        return run_sdk(adapter_identifier, adapter_type, params)
    raise ValueError(f"Unsupported adapter '{adapter_identifier}'")


@celery_app.task(name="cloudarena.health.ping")
def ping() -> str:
    return "pong"


@celery_app.task(name="cloudarena.run.execute_runbook", acks_late=False, max_retries=0)
def execute_runbook(run_id: str, runbook: Dict[str, Any]) -> str:
    steps: List[Dict[str, Any]] = runbook.get("steps", [])
    techniques = _load_techniques()

    for index, step in enumerate(steps, start=1):
        technique_id = step.get("technique_id")
        params = step.get("params", {}) or {}

        spec = techniques.get(technique_id)
        severity = spec.severity if spec else None
        adapter_type, adapter_identifier = _resolve_adapter(spec)
        resource = params.get("bucket") if adapter_type == "stratus" else None
        artifacts: List[Dict[str, Any]] = []

        step_payload = {
            "index": index,
            "technique_id": technique_id,
            "params": params,
        }

        try:
            _post_event(
                run_id,
                "run.step",
                step_payload,
                phase="queued",
                severity=severity,
                resource=resource,
            )

            _post_event(
                run_id,
                "run.step",
                step_payload,
                phase="running",
                severity=severity,
                resource=resource,
            )

            with _step_timeout(STEP_TIMEOUT_SECONDS):
                result = _run_step(adapter_type, adapter_identifier, params)

            stdout_content = result.get("stdout")
            if stdout_content:
                artifact_uri = _write_stdout_artifact(run_id, index, stdout_content)
                artifacts.append({"type": "stdout", "uri": artifact_uri})

            cloudtrail_uri = _cloudtrail_artifact_uri()
            if cloudtrail_uri and adapter_type == "stratus":
                artifacts.append({"type": "cloudtrail", "uri": cloudtrail_uri})

            if result.get("ok", False):
                _post_event(
                    run_id,
                    "run.step",
                    {**step_payload, "result": result},
                    phase="ok",
                    severity=severity,
                    resource=resource,
                    artifacts=artifacts or None,
                )
            else:
                raise StepExecutionError(technique_id, result)

        except StepTimeoutError as exc:
            logger.error("Step %s timed out: %s", technique_id, exc)
            _post_event(
                run_id,
                "run.step",
                {**step_payload, "error": str(exc)},
                phase="error",
                severity=severity,
                resource=resource,
                artifacts=artifacts or None,
            )
            raise
        except httpx.HTTPError as exc:
            logger.error("Failed to emit event for run %s step %s: %s", run_id, technique_id, exc)
            raise
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Error executing step %s", technique_id)
            stderr_message = getattr(exc, "stderr", None)
            error_payload = {**step_payload, "error": str(exc)}
            if stderr_message:
                error_payload["stderr"] = stderr_message
            result_payload = getattr(exc, "result", None)
            if result_payload:
                error_payload["result"] = result_payload
            _post_event(
                run_id,
                "run.step",
                error_payload,
                phase="error",
                severity=severity,
                resource=resource,
                artifacts=artifacts or None,
            )
            raise

    _post_event(
        run_id,
        "run.completed",
        {"status": "ok", "step_count": len(steps)},
        phase="ok",
    )

    return "queued"
