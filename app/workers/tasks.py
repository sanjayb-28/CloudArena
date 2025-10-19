import logging
import signal
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

import httpx

from app.adapters import sdk as sdk_adapter
from app.adapters import stratus as stratus_adapter
from app.ingest import normalize_result
from app.planner import get_technique_catalog
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
def _step_timeout(seconds: int) -> Generator[None, None, None]:
    if seconds <= 0:
        yield
        return

    if threading.current_thread() is not threading.main_thread():
        # SIGALRM cannot be used from worker threads; fall back to no-op timeout.
        yield
        return

    def _handle_timeout(signum, frame):  # noqa: ARG001
        raise StepTimeoutError(f"Step execution timed out after {seconds} seconds.")

    try:
        previous = signal.signal(signal.SIGALRM, _handle_timeout)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
    except ValueError:
        # signal.signal can raise ValueError if the platform/thread disallows SIGALRM.
        yield


def _post_event(
    run_id: str,
    event_type: str,
    payload: Dict[str, Any],
    *,
    phase: Optional[str] = None,
    severity: Optional[str] = None,
    resource: Optional[str] = None,
    artifacts: Optional[List[Dict[str, Any]]] = None,
    summary: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
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
    if summary is not None:
        event_body["summary"] = summary
    if details is not None:
        event_body["details"] = details

    backoff = 1.0
    attempt = 0
    max_attempts = 5

    while True:
        attempt += 1
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(url, json=event_body, headers=headers)
                response.raise_for_status()
            return
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            if status_code < 500 and status_code not in {429}:
                raise
        except httpx.RequestError:
            pass

        if attempt >= max_attempts:
            raise

        time.sleep(backoff)
        backoff = min(backoff * 2, 8.0)


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
        return stratus_adapter.run_stratus(adapter_identifier, adapter_type, params, timeout=STEP_TIMEOUT_SECONDS)
    if adapter_type == "sdk" and adapter_identifier:
        return sdk_adapter.run_sdk(adapter_identifier, adapter_type, params)
    raise ValueError(f"Unsupported adapter '{adapter_identifier}'")


@celery_app.task(name="cloudarena.health.ping")
def ping() -> str:
    return "pong"


@celery_app.task(name="cloudarena.run.execute_runbook", acks_late=False, max_retries=0)
def execute_runbook(run_id: str, runbook: Dict[str, Any]) -> str:
    steps: List[Dict[str, Any]] = runbook.get("steps", [])
    techniques = get_technique_catalog()

    current_index: Optional[int] = None
    current_technique: Optional[str] = None

    final_status = "ok"

    try:
        for index, step in enumerate(steps, start=1):
            current_index = index
            technique_id = step.get("technique_id")
            current_technique = technique_id
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
                    summary="Step queued",
                    details=None,
                )

                _post_event(
                    run_id,
                    "run.step",
                    step_payload,
                    phase="running",
                    severity=severity,
                    resource=resource,
                    summary="Step running",
                    details=None,
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
                    effective_severity, summary, details, result_artifacts = normalize_result(
                        technique_id,
                        result,
                        severity,
                    )
                    if result_artifacts:
                        artifacts.extend(result_artifacts)

                    _post_event(
                        run_id,
                        "run.step",
                        {**step_payload, "result": result},
                        phase="ok",
                        severity=effective_severity,
                        resource=resource,
                        artifacts=artifacts or None,
                        summary=summary,
                        details=details,
                    )
                else:
                    raise StepExecutionError(technique_id, result)

            except StepTimeoutError as exc:
                logger.error("Step %s timed out: %s", technique_id, exc)
                final_status = "error"
                _post_event(
                    run_id,
                    "run.step",
                    {**step_payload, "error": str(exc)},
                    phase="error",
                    severity=severity,
                    resource=resource,
                    artifacts=artifacts or None,
                    summary=f"Step timed out: {exc}",
                    details=None,
                )
                raise
            except httpx.HTTPError as exc:
                logger.error("Failed to emit event for run %s step %s: %s", run_id, technique_id, exc)
                final_status = "error"
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
                    summary=f"Step error: {exc}",
                    details=None,
                )
                final_status = "error"
                raise
    except Exception as execution_error:
        logger.error("Run %s failed: %s", run_id, execution_error)
        failure_payload: Dict[str, Any] = {
            "status": "error",
            "step_count": len(steps),
            "error": str(execution_error),
        }
        if current_index is not None:
            failure_payload["failed_step"] = {
                "index": current_index,
                "technique_id": current_technique,
            }
        try:
            _post_event(
                run_id,
                "run.completed",
                failure_payload,
                phase="error",
                severity="high",
                summary=f"Run failed: {execution_error}",
                details=None,
            )
        except Exception:  # pylint: disable=broad-except
            logger.exception("Failed to emit run completion error event for %s", run_id)
        final_status = "error"
        raise
    else:
        _post_event(
            run_id,
            "run.completed",
            {"status": "ok", "step_count": len(steps)},
            phase="ok",
            severity="low",
            summary="Run completed successfully",
            details=None,
        )

    return final_status
