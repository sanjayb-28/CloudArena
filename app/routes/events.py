import json
from typing import Any, Dict, List

from fastapi import APIRouter, Depends

from app.auth import require_auth
from app.models import Event
from app.store import insert_event, list_events

router = APIRouter()


@router.post("/events")
async def create_event(event: Event, _: Dict[str, Any] = Depends(require_auth)) -> Dict[str, str]:
    artifacts_json = None
    if event.artifacts:
        artifacts_json = json.dumps([artifact.model_dump() for artifact in event.artifacts])

    payload = dict(event.payload)
    payload.setdefault("event_type", event.event_type)

    status = payload.get("status") or event.phase
    payload.setdefault("status", status)

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
    )
    return {"status": "accepted"}


@router.get("/events/{run_id}")
async def get_events(run_id: str, _: Dict[str, Any] = Depends(require_auth)) -> Dict[str, List[Dict[str, Any]]]:
    events = list_events(run_id)
    return {"events": events}
