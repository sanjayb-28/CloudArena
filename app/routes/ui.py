import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth import require_auth
from app.planner import Runbook
from app.reporter import render_report
from app.routes import runs as run_routes
from app.routes.facts import gather_facts
from app.store import get_run, list_events, list_runs

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _prepare_run_record(record: Dict[str, Any]) -> Dict[str, Any]:
    prepared = record.copy()
    try:
        raw = json.loads(prepared.get("runbook_json") or "{}")
    except json.JSONDecodeError:
        raw = {}

    if isinstance(raw, dict):
        try:
            prepared["runbook"] = Runbook.model_validate(raw)
        except Exception:  # pylint: disable=broad-except
            prepared["runbook"] = Runbook(run_id=prepared.get("run_id", "unknown"))
    else:
        prepared["runbook"] = Runbook(run_id=prepared.get("run_id", "unknown"))

    return prepared


@router.get("/ui", response_class=HTMLResponse)
async def ui_dashboard(request: Request, _: Dict[str, Any] = Depends(require_auth)) -> HTMLResponse:
    recent_runs = [_prepare_run_record(run) for run in list_runs(limit=20)]
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "runs": recent_runs,
            "error": None,
        },
    )


@router.post("/ui/runs", response_class=HTMLResponse)
async def ui_create_run(
    request: Request,
    goals: Optional[str] = Form(None),
    _: Dict[str, Any] = Depends(require_auth),
):
    payload = run_routes.RunRequest(goals=goals or None)
    try:
        result = await run_routes.create_run(payload, {})
    except HTTPException as exc:
        recent_runs = [_prepare_run_record(run) for run in list_runs(limit=20)]
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "runs": recent_runs,
                "error": exc.detail,
            },
            status_code=exc.status_code,
        )

    run_id = result["run_id"]
    return RedirectResponse(f"/ui/runs/{run_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/ui/runs/{run_id}", response_class=HTMLResponse)
async def ui_run_detail(
    request: Request,
    run_id: str,
    _: Dict[str, Any] = Depends(require_auth),
) -> HTMLResponse:
    record = get_run(run_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found.")

    prepared = _prepare_run_record(record)
    runbook = prepared.get("runbook")
    if not isinstance(runbook, Runbook):
        runbook = Runbook(run_id=run_id)
    events = list_events(run_id)

    return templates.TemplateResponse(
        "run_detail.html",
        {
            "request": request,
            "run": prepared,
            "runbook": runbook,
            "events": events,
        },
    )


@router.post("/ui/runs/{run_id}/reports", response_class=HTMLResponse)
async def ui_run_report(
    run_id: str,
    _: Dict[str, Any] = Depends(require_auth),
) -> HTMLResponse:
    events = list_events(run_id)
    if not events:
        return HTMLResponse("<p>No events yet for this run.</p>")
    facts = await gather_facts()
    markdown = render_report(facts, events)
    html = f"<pre class='report-output'>{markdown}</pre>"
    return HTMLResponse(html)
