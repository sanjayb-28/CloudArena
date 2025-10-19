import json
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth import get_current_user_optional
from app.reporter import render_report
from app.routes import runs as run_routes
from app.routes.facts import gather_facts
from app.store import get_run, list_events, list_runs

router = APIRouter()
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _prepare_run_record(record: Dict[str, Any]) -> Dict[str, Any]:
    prepared = record.copy()
    runbook_value = prepared.get("runbook")
    if isinstance(runbook_value, dict):
        prepared["runbook"] = runbook_value
    else:
        try:
            prepared["runbook"] = json.loads(prepared.get("runbook_json") or "{}")
        except json.JSONDecodeError:
            prepared["runbook"] = {}

    if not isinstance(prepared["runbook"], dict):
        prepared["runbook"] = {}

    facts_raw = prepared.get("facts")
    if isinstance(facts_raw, dict):
        prepared["facts"] = facts_raw
    else:
        facts_json = prepared.get("facts_json")
        if isinstance(facts_json, str):
            try:
                prepared["facts"] = json.loads(facts_json)
            except json.JSONDecodeError:
                prepared["facts"] = None
        else:
            prepared["facts"] = None

    return prepared


@router.get("/ui", response_class=HTMLResponse)
async def ui_dashboard(request: Request, user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)) -> HTMLResponse:
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    recent_runs = [_prepare_run_record(run) for run in list_runs(limit=20)]
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "runs": recent_runs,
            "error": None,
            "user": user,
        },
    )


@router.post("/ui/runs", response_class=HTMLResponse)
async def ui_create_run(
    request: Request,
    goals: Optional[str] = Form(None),
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional),
):
    if not user:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
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
                "user": user,
            },
            status_code=exc.status_code,
        )

    run_id = result["run_id"]
    return RedirectResponse(f"/ui/runs/{run_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/ui/runs/{run_id}", response_class=HTMLResponse)
async def ui_run_detail(
    request: Request,
    run_id: str,
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional),
) -> HTMLResponse:
    if not user:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    record = get_run(run_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found.")

    prepared = _prepare_run_record(record)
    runbook = prepared.get("runbook") or {}
    events = list_events(run_id)

    return templates.TemplateResponse(
        "run_detail.html",
        {
            "request": request,
            "run": prepared,
            "runbook": runbook,
            "events": events,
            "user": user,
        },
    )


@router.post("/ui/runs/{run_id}/reports", response_class=HTMLResponse)
async def ui_run_report(
    run_id: str,
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional),
) -> HTMLResponse:
    if not user:
        return HTMLResponse("<p>Authentication required.</p>", status_code=status.HTTP_401_UNAUTHORIZED)
    events = list_events(run_id)
    if not events:
        return HTMLResponse("<p>No events yet for this run.</p>")
    facts = await gather_facts()
    markdown = render_report(facts, events)
    try:
        import markdown2

        html_body = markdown2.markdown(markdown, extras=["tables", "fenced-code-blocks"])
        html = f"<div class='report-output-html'>{html_body}</div>"
    except Exception:  # pylint: disable=broad-except
        html = f"<pre class='report-output'>{markdown}</pre>"
    return HTMLResponse(html)
