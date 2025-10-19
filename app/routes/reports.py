import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth import require_auth
from app.reporter.reporter import render_report
from app.store import get_run, list_events

router = APIRouter()


class ReportRequest(BaseModel):
    facts: Optional[Dict[str, Any]] = None


@router.post("/reports/{run_id}")
async def create_report(
    run_id: str,
    payload: ReportRequest,
    _: Dict[str, Any] = Depends(require_auth),
) -> Dict[str, str]:
    events = list_events(run_id)
    if not events and not get_run(run_id):
        raise HTTPException(status_code=404, detail="Run not found.")

    if payload.facts is not None:
        facts = payload.facts
    else:
        run_record = get_run(run_id)
        facts = None
        if run_record:
            if isinstance(run_record.get("facts"), dict):
                facts = run_record["facts"]
            elif isinstance(run_record.get("facts_json"), str):
                try:
                    facts = json.loads(run_record["facts_json"])
                except json.JSONDecodeError:
                    facts = None
        if facts is None:
            facts = {}

    markdown = render_report(facts, events)
    return {"markdown": markdown}
