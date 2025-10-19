import json
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates

from app.auth import require_auth
from app.models import Event
from app.store import insert_event, list_events, update_run_status

router = APIRouter()
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.post("/events")
async def create_event(event: Event, _: Dict[str, Any] = Depends(require_auth)) -> Dict[str, str]:
    artifacts_json = None
    if event.artifacts:
        artifacts_json = json.dumps([artifact.model_dump() for artifact in event.artifacts])

    payload = dict(event.payload)
    payload.setdefault("event_type", event.event_type)

    status = payload.get("status") or event.phase
    payload.setdefault("status", status)

    summary = event.summary or payload.get("summary")
    details = event.details or payload.get("details")
    details_json = json.dumps(details) if isinstance(details, dict) else None

    insert_event(
        run_id=event.run_id,
        ts=event.created_at.isoformat(),
        technique_id=payload.get("technique_id") or None,
        phase=event.phase,
        status=status,
        severity=event.severity,
        resource=event.resource,
        artifacts_json=artifacts_json,
        payload=payload,
        summary=summary,
        details_json=details_json,
    )

    event_type = payload.get("event_type")
    if event_type == "run.created":
        update_run_status(event.run_id, "queued")
    elif event_type == "run.step":
        phase = event.phase or payload.get("phase")
        if phase == "running":
            update_run_status(event.run_id, "running")
        elif phase == "error":
            update_run_status(event.run_id, "error")
    elif event_type == "run.completed":
        final_status = payload.get("status") or status or "unknown"
        update_run_status(event.run_id, final_status, completed_at=event.created_at)

    return {"status": "accepted"}


@router.get("/events/{run_id}")
async def get_events(
    request: Request,
    run_id: str,
    _: Dict[str, Any] = Depends(require_auth),
):
    events = list_events(run_id)
    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(
            "events_fragment.html",
            {
                "request": request,
                "run_id": run_id,
                "events": events,
            },
            media_type="text/html",
        )

    return {"events": events}
