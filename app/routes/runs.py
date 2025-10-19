import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.auth import require_auth
from app.models import RunStep, Runbook
from app.planner import get_technique_spec, plan
from app.routes.facts import gather_facts
from app.settings import get_settings
from app.store import (
    get_run as store_get_run,
    insert_event,
    insert_run,
    list_runs as store_list_runs,
)
from app.workers.tasks import execute_runbook

settings = get_settings()

router = APIRouter()


class RunRequest(BaseModel):
    goals: Optional[str] = None
    facts: Optional[Dict[str, Any]] = None


class RunRecord(BaseModel):
    run_id: str
    goals: Optional[str]
    status: Optional[str]
    created_at: str
    completed_at: Optional[str]
    runbook: Dict[str, Any]
    facts: Optional[Dict[str, Any]]


class RunsResponse(BaseModel):
    runs: List[RunRecord]


def _serialize_run_record(record: Dict[str, Any]) -> RunRecord:
    runbook_data = record.get("runbook") if isinstance(record.get("runbook"), dict) else {}
    if isinstance(runbook_data, dict):
        runbook_data.setdefault("run_id", record.get("run_id"))

    facts_value = record.get("facts") if isinstance(record.get("facts"), dict) else None
    if facts_value is None:
        facts_json = record.get("facts_json")
        if isinstance(facts_json, str):
            try:
                facts_value = json.loads(facts_json)
            except json.JSONDecodeError:
                facts_value = None

    return RunRecord(
        run_id=record.get("run_id"),
        goals=record.get("goals"),
        status=record.get("status"),
        created_at=record.get("created_at"),
        completed_at=record.get("completed_at"),
        runbook=runbook_data,
        facts=facts_value,
    )


@router.post("/runs")
async def create_run(
    payload: RunRequest,
    _: Dict[str, Any] = Depends(require_auth),
) -> Dict[str, Any]:
    allowed_region = settings.region
    try:
        sts_client = boto3.client("sts", region_name=allowed_region)
    except NoCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AWS credentials are not available.",
        ) from exc

    try:
        identity = sts_client.get_caller_identity()
    except ClientError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to validate AWS caller identity.",
        ) from exc

    account_id = identity.get("Account")
    if settings.arena_account_id and account_id != settings.arena_account_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Lab-only account mismatch.")

    session_region = boto3.session.Session().region_name
    if allowed_region and session_region and session_region != allowed_region:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Region not allowed for CloudArena runs.")

    goals = payload.goals
    if payload.facts is not None:
        facts = payload.facts
    else:
        facts = await gather_facts()

    if not isinstance(facts, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Facts payload must be an object.")

    facts_region = facts.get("region")
    if allowed_region and facts_region and facts_region != allowed_region:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Region not allowed for CloudArena runs.")

    if facts.get("account") and facts.get("account") != account_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Facts account does not match caller.")

    runbook_spec = plan(facts, goals)

    allowed_adapters = {"sdk", "stratus"}
    for step_spec in runbook_spec.steps:
        spec = get_technique_spec(step_spec.technique_id)
        if not spec:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown technique '{step_spec.technique_id}'.",
            )
        adapter_value = (spec.impl or {}).get("adapter")
        if not adapter_value or not isinstance(adapter_value, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Technique '{step_spec.technique_id}' is missing an adapter mapping.",
            )
        adapter_prefix = adapter_value.split(".", 1)[0]
        if adapter_prefix not in allowed_adapters:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Technique '{step_spec.technique_id}' uses unsupported adapter '{adapter_value}'.",
            )

    run_id = str(uuid4())

    steps = [RunStep(technique_id=step.technique_id, params=step.params, notes=step.notes) for step in runbook_spec.steps]
    runbook = Runbook(run_id=run_id, goals=runbook_spec.goals, steps=steps)

    insert_run(
        run_id,
        goals,
        json.dumps(runbook.model_dump()),
        json.dumps(facts),
        "queued",
    )

    expires_at = datetime.utcnow() + timedelta(minutes=15)
    execute_runbook.apply_async(args=(run_id, runbook.model_dump()), expires=expires_at)

    insert_event(
        run_id=run_id,
        ts=datetime.utcnow().isoformat(),
        technique_id=None,
        phase="queued",
        status="created",
        severity=None,
        resource=None,
        artifacts_json=None,
        summary="Run created",
        payload={
            "event_type": "run.created",
            "status": "created",
            "step_count": len(steps),
            "goals": goals,
        },
    )

    return {
        "run_id": run_id,
        "runbook": runbook.model_dump(),
        "facts": facts,
        "status": "queued",
    }


@router.get("/runs", response_model=RunsResponse)
async def list_runs_endpoint(
    limit: int = 20,
    _: Dict[str, Any] = Depends(require_auth),
) -> RunsResponse:
    records = store_list_runs(limit=limit)
    return RunsResponse(runs=[_serialize_run_record(record) for record in records])


@router.get("/runs/{run_id}", response_model=RunRecord)
async def get_run_endpoint(
    run_id: str,
    _: Dict[str, Any] = Depends(require_auth),
) -> RunRecord:
    record = store_get_run(run_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found.")
    return _serialize_run_record(record)
