from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth import require_auth
from app.models import Event, RunStep, Runbook
from app.planner import plan
from app.routes.events import record_event
from app.routes.facts import gather_facts
from app.workers.celery_app import execute_runbook

router = APIRouter()


class RunRequest(BaseModel):
    goals: Optional[str] = None
    facts: Optional[Dict[str, Any]] = None


@router.post("/runs")
async def create_run(
    payload: RunRequest,
    _: Dict[str, Any] = Depends(require_auth),
) -> Dict[str, Any]:
    goals = payload.goals
    if payload.facts is not None:
        facts = payload.facts
    else:
        facts = await gather_facts()

    runbook_spec = plan(facts, goals)
    run_id = str(uuid4())

    steps = [RunStep(technique_id=step.technique_id, params=step.params, notes=step.notes) for step in runbook_spec.steps]
    runbook = Runbook(run_id=run_id, goals=runbook_spec.goals, steps=steps)

    execute_runbook.delay(run_id, runbook.model_dump())

    record_event(
        Event(
            run_id=run_id,
            event_type="run.created",
            payload={"step_count": len(steps), "goals": goals},
        )
    )

    return {
        "run_id": run_id,
        "runbook": runbook.model_dump(),
        "facts": facts,
    }
