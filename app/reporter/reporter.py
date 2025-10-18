from __future__ import annotations

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
    summary_section, table_section, remediation_section = _build_sections(facts, events)

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
        summary_section,
        "",
        table_section,
        "",
        "## S3 Inventory",
        _summarize_s3(facts),
        "",
        remediation_section,
        "",
        "## Run Telemetry",
        _summarize_events(events),
    ]

    return "\n".join(sections)


def _render_with_gemini(facts: dict, events: Sequence[dict]) -> str:
    summary_section, table_section, remediation_section = _build_sections(facts, events)

    settings = get_settings()
    prompt = f"""Rewrite the following CloudArena security exercise summary in concise executive prose.

Summary:
{summary_section}

Recommended remediation actions:
{remediation_section}

Return two sections:
1. Executive Summary (2-3 sentences)
2. Remediation Recommendations (bullet list)"""

    try:
        import google.generativeai as genai  # type: ignore

        genai.configure(api_key=settings.gemini_api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        if not response or not response.text:
            raise ValueError("Empty response from Gemini")
        generated = response.text.strip()
    except Exception as exc:  # pylint: disable=broad-except
        raise RuntimeError(f"Gemini generation failed: {exc}") from exc

    sections = [
        "# CloudArena Run Report",
        generated,
        "",
        table_section,
    ]

    return "\n".join(sections)


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


def _build_sections(facts: dict, events: Sequence[dict]) -> tuple[str, str, str]:
    step_records = _aggregate_steps(events)
    summary_section = _build_summary_section(step_records, events)
    table_section = _build_table_section(step_records)
    remediation_section = _build_remediation_section(facts)
    return summary_section, table_section, remediation_section


def _aggregate_steps(events: Sequence[dict]) -> dict[tuple[int | None, str | None], dict[str, Any]]:
    steps: dict[tuple[int | None, str | None], dict[str, Any]] = {}
    for event in events:
        payload = event.get("payload", {}) or {}
        if payload.get("event_type") != "run.step":
            continue
        index = payload.get("index")
        technique_id = payload.get("technique_id")
        key = (index, technique_id)
        steps[key] = {
            "index": index,
            "technique_id": technique_id,
            "severity": event.get("severity") or payload.get("severity"),
            "resource": event.get("resource") or payload.get("resource"),
            "phase": event.get("phase"),
            "status": payload.get("status") or event.get("status"),
            "artifacts": event.get("artifacts", []),
        }
    return steps


def _build_summary_section(steps: dict[tuple[int | None, str | None], dict[str, Any]], events: Sequence[dict]) -> str:
    total = len(steps)
    ok_count = sum(
        1 for record in steps.values() if (record.get("status") or record.get("phase") or "").lower() == "ok"
    )
    error_count = sum(
        1 for record in steps.values() if (record.get("status") or record.get("phase") or "").lower() == "error"
    )
    final_status = "unknown"
    for event in reversed(events):
        payload = event.get("payload", {}) or {}
        if payload.get("event_type") == "run.completed":
            final_status = payload.get("status", event.get("status", final_status))
            break

    lines = [
        "## Executive Summary",
        f"- Steps executed: **{total}**",
        f"- Successful steps: **{ok_count}**",
        f"- Failed steps: **{error_count}**",
        f"- Final run status: **{final_status}**",
    ]
    return "\n".join(lines)


def _build_table_section(steps: dict[tuple[int | None, str | None], dict[str, Any]]) -> str:
    if not steps:
        return "## Techniques\nNo technique execution data available."

    header = "## Techniques\n| Technique | Severity | Resource | Status | Key Evidence |\n| --- | --- | --- | --- | --- |"
    rows = [header]
    for key in sorted(steps.keys(), key=lambda item: (item[0] is None, item[0] if isinstance(item[0], int) else 0)):
        record = steps[key]
        technique = record.get("technique_id") or "unknown"
        severity_value = record.get("severity")
        severity = severity_value.title() if isinstance(severity_value, str) else "n/a"
        resource = record.get("resource") or "n/a"
        status = record.get("status") or record.get("phase") or "unknown"

        artifacts = record.get("artifacts") or []
        evidence = ", ".join(a.get("uri") or a.get("type") for a in artifacts if isinstance(a, dict)) or "n/a"

        rows.append(f"| {technique} | {severity} | {resource} | {status} | {evidence} |")

    return "\n".join(rows)


def _build_remediation_section(facts: dict) -> str:
    services = facts.get("services", {}) or {}
    s3_buckets = services.get("s3", []) or []
    remediations: list[str] = []

    public_buckets = [bucket for bucket in s3_buckets if bucket.get("public")]
    for bucket in public_buckets:
        name = bucket.get("name") or "the bucket"
        remediations.append(
            f"- Restrict public access to `{name}` by enabling S3 Block Public Access and removing public ACLs or bucket policies."
        )

    if not remediations:
        remediations.append("- No immediate remediation actions identified from this run.")

    return "## Remediation\n" + "\n".join(remediations)
