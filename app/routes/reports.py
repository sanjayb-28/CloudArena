from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth import require_auth
from app.reporter.reporter import render_report
from app.routes.events import get_events_for_run
from app.routes.facts import gather_facts

router = APIRouter()


class ReportRequest(BaseModel):
    facts: Optional[Dict[str, Any]] = None


@router.post("/reports/{run_id}")
async def create_report(
    run_id: str,
    payload: ReportRequest,
    _: Dict[str, Any] = Depends(require_auth),
) -> Dict[str, str]:
    events = get_events_for_run(run_id)
    if not events:
        raise HTTPException(status_code=404, detail="Run not found.")

    if payload.facts is not None:
        facts = payload.facts
    else:
        facts = await gather_facts()

    markdown = render_report(facts, events)
    return {"markdown": markdown}
