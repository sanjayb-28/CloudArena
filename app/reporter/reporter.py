from collections import Counter
from typing import Any, Iterable, Sequence

from app.settings import get_settings


def _summarize_s3(facts: dict) -> str:
    services = facts.get("services", {}) or {}
    s3_buckets = services.get("s3", []) or []

    if not s3_buckets:
        return "No S3 inventory available."

    lines = ["| Bucket | Public |", "| --- | --- |"]
    for bucket in s3_buckets:
        name = bucket.get("name", "unknown")
        public = "yes" if bucket.get("public") else "no"
        lines.append(f"| {name} | {public} |")
    return "\n".join(lines)


def _summarize_events(events: Sequence[dict]) -> str:
    if not events:
        return "No events recorded for this run."

    counter = Counter()
    for event in events:
        if event.get("event_type") == "run.step":
            status = event.get("payload", {}).get("status", "unknown")
            counter[status] += 1

    lines = ["### Step Outcomes"]
    if counter:
        for status, count in sorted(counter.items()):
            lines.append(f"- {status}: {count}")
    else:
        lines.append("- No step-level telemetry captured.")

    completion = [e for e in events if e.get("event_type") == "run.completed"]
    if completion:
        payload = completion[-1].get("payload", {})
        lines.append(
            f"\nFinal status: **{payload.get('status', 'unknown')}** "
            f"(steps: {payload.get('step_count', 'n/a')})"
        )

    return "\n".join(lines)


def _render_static_markdown(facts: dict, events: Sequence[dict]) -> str:
    settings = get_settings()
    account = facts.get("account", "unknown")
    region = facts.get("region") or settings.region

    sections = [
        "# CloudArena Run Report",
        "## Environment Overview",
        f"- Environment: `{settings.env}`",
        f"- AWS Account: `{account}`",
        f"- Region: `{region}`",
        "",
        "## S3 Inventory",
        _summarize_s3(facts),
        "",
        "## Run Telemetry",
        _summarize_events(events),
    ]

    return "\n".join(sections)


def _render_with_gemini(facts: dict, events: Sequence[dict]) -> str:
    raise NotImplementedError


def render_report(facts: dict, events: Iterable[Any]) -> str:
    event_dicts = []
    for event in events:
        if hasattr(event, "model_dump"):
            event_dicts.append(event.model_dump())
        elif hasattr(event, "dict"):
            event_dicts.append(event.dict())
        else:
            event_dicts.append(dict(event))

    settings = get_settings()
    if settings.gemini_api_key:
        try:
            return _render_with_gemini(facts, event_dicts)
        except Exception:
            pass

    return _render_static_markdown(facts, event_dicts)
