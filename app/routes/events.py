from collections import defaultdict
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from app.auth import require_auth
from app.models import Event

router = APIRouter()

_EVENTS: Dict[str, List[Event]] = defaultdict(list)


def record_event(event: Event) -> None:
    _EVENTS[event.run_id].append(event)


def get_events_for_run(run_id: str) -> List[Event]:
    return _EVENTS.get(run_id, [])


@router.post("/events")
async def create_event(event: Event, _: Dict[str, Any] = Depends(require_auth)) -> Dict[str, str]:
    record_event(event)
    return {"status": "accepted"}


@router.get("/events/{run_id}")
async def get_events(run_id: str, _: Dict[str, Any] = Depends(require_auth)) -> Dict[str, List[Event]]:
    if run_id not in _EVENTS:
        raise HTTPException(status_code=404, detail="Run not found.")
    return {"events": _EVENTS[run_id]}
