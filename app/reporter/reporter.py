from __future__ import annotations

import json
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from app.settings import get_settings

SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3}


def render_report(facts: dict, events: Iterable[Any]) -> str:
    event_dicts: List[Dict[str, Any]] = []
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


def _render_static_markdown(facts: dict, events: Sequence[dict]) -> str:
    summary_md, _, findings_table, remediation_md, _, step_records = _prepare_sections(facts, events)

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
        summary_md,
        "",
        findings_table,
        "",
        "## S3 Inventory",
        _summarize_s3(facts),
        "",
        remediation_md,
        "",
        "## Run Telemetry",
        _summarize_events(events, step_records),
    ]

    return "\n".join(sections)


def _render_with_gemini(facts: dict, events: Sequence[dict]) -> str:
    summary_md, summary_plain, findings_table, remediation_md, remediation_plain, step_records = _prepare_sections(
        facts, events
    )

    settings = get_settings()
    prompt = f"""Rewrite the following CloudArena security exercise summary in concise executive prose.\n\nSummary:\n{summary_plain}\n\nRecommended remediation actions:\n{remediation_plain}\n\nReturn two sections:\n1. Executive Summary (2-3 sentences)\n2. Remediation Recommendations (bullet list)"""

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
        findings_table,
        "",
        remediation_md,
        "",
        "## Run Telemetry",
        _summarize_events(events, step_records),
    ]

    return "\n".join(sections)


def _prepare_sections(
    facts: dict, events: Sequence[dict]
) -> Tuple[str, str, str, str, str, List[Dict[str, Any]]]:
    steps = _aggregate_steps(events)
    summary_md, summary_plain = _build_summary_section(steps)
    findings_table = _build_findings_table(steps)
    remediation_md, remediation_plain = _build_remediation_section(facts, steps)
    return summary_md, summary_plain, findings_table, remediation_md, remediation_plain, steps


def _aggregate_steps(events: Sequence[dict]) -> List[Dict[str, Any]]:
    steps: Dict[Tuple[int, Optional[str]], Dict[str, Any]] = {}
    for event in events:
        payload = event.get("payload", {}) or {}
        if payload.get("event_type") != "run.step":
            continue
        index = payload.get("index")
        technique_id = payload.get("technique_id")
        key = (index or 0, technique_id)
        record = steps.setdefault(
            key,
            {
                "index": index,
                "technique_id": technique_id,
                "severity": None,
                "status": None,
                "phase": None,
                "summary": None,
                "details": {},
                "findings": [],
                "artifacts": [],
                "resource": None,
            },
        )
        record["severity"] = event.get("severity") or payload.get("severity") or record.get("severity")
        record["status"] = payload.get("status") or event.get("status") or record.get("status")
        record["phase"] = event.get("phase") or record.get("phase")
        record["resource"] = event.get("resource") or payload.get("resource") or record.get("resource")
        summary = event.get("summary") or payload.get("summary")
        if summary:
            record["summary"] = summary
        details = event.get("details") or payload.get("details")
        if details:
            record["details"] = details
            findings = details.get("findings")
            if isinstance(findings, list):
                record["findings"] = findings
        else:
            result = payload.get("result")
            if isinstance(result, dict):
                findings = result.get("findings")
                if isinstance(findings, list):
                    record["findings"] = findings
        artifacts = event.get("artifacts") or payload.get("artifacts") or []
        if artifacts:
            record.setdefault("artifacts", []).extend(artifacts)
    return [
        steps[key]
        for key in sorted(
            steps.keys(), key=lambda item: (item[0] is None, item[0] if item[0] is not None else 0, item[1] or "")
        )
    ]


def _build_summary_section(steps: List[Dict[str, Any]]) -> Tuple[str, str]:
    severity_counts = Counter((record.get("severity") or "informational").lower() for record in steps)

    parts = [
        f"High: **{severity_counts.get('high', 0)}**",
        f"Medium: **{severity_counts.get('medium', 0)}**",
    ]
    if severity_counts.get("low", 0):
        parts.append(f"Low: **{severity_counts.get('low', 0)}**")
    if severity_counts.get("informational", 0):
        parts.append(f"Informational: **{severity_counts.get('informational', 0)}**")

    summary_lines = [
        "## Executive Summary",
        "- " + " | ".join(parts),
    ]

    ranked_steps = sorted(
        steps,
        key=lambda rec: (
            -SEVERITY_ORDER.get((rec.get("severity") or "low").lower(), 0),
            -(len(rec.get("findings") or [])),
        ),
    )

    top_risk_entries: List[str] = []
    for rec in ranked_steps:
        severity = (rec.get("severity") or "informational").lower()
        findings = rec.get("findings") or []
        if severity == "informational" and not findings:
            continue
        summary_text = rec.get("summary") or _default_summary(rec)
        top_risk_entries.append(f"- **{rec.get('technique_id') or 'Unknown'}**: {summary_text}")
        if len(top_risk_entries) == 3:
            break

    if top_risk_entries:
        summary_lines.append("### Top Risks")
        summary_lines.extend(top_risk_entries)
    else:
        summary_lines.append("### Top Risks\n- No significant risks detected.")

    summary_markdown = "\n".join(summary_lines)
    summary_plain = "\n".join(line.lstrip("- ") for line in summary_lines if line.startswith("- "))
    summary_plain += "\n" + "\n".join(top_risk_entries)
    return summary_markdown, summary_plain.strip()


def _default_summary(record: Dict[str, Any]) -> str:
    findings = record.get("findings") or []
    if findings:
        return f"{len(findings)} findings detected"
    return "No findings reported"


def _build_findings_table(steps: List[Dict[str, Any]]) -> str:
    if not steps:
        return "## Findings\nNo findings recorded."

    header = "## Findings\n| Technique | Severity | Resource | Issue | Evidence |\n| --- | --- | --- | --- | --- |"
    rows = [header]
    for record in steps:
        technique = record.get("technique_id") or "unknown"
        findings = record.get("findings") or []
        if findings:
            for finding in findings:
                severity = (finding.get("severity") or record.get("severity") or "informational").title()
                resource = finding.get("resource") or record.get("resource") or "n/a"
                issue = finding.get("issue") or record.get("summary") or "n/a"
                evidence = _format_evidence(finding.get("evidence"))
                rows.append(f"| {technique} | {severity} | {resource} | {issue} | {evidence} |")
        else:
            severity = (record.get("severity") or "informational").title()
            resource = record.get("resource") or "n/a"
            issue = record.get("summary") or _default_summary(record)
            evidence = _format_evidence(record.get("details"))
            rows.append(f"| {technique} | {severity} | {resource} | {issue} | {evidence} |")

    return "\n".join(rows)


def _format_evidence(evidence: Any, limit: int = 160) -> str:
    if not evidence:
        return "n/a"
    if isinstance(evidence, str):
        text = evidence
    else:
        try:
            text = json.dumps(evidence, default=str)
        except TypeError:
            text = str(evidence)
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text.replace("\n", " ")


def _build_remediation_section(facts: dict, steps: List[Dict[str, Any]]) -> Tuple[str, str]:
    remediation_map = {
        "T-EC2-SG-OPEN": "Restrict security group source CIDRs, remove 0.0.0.0/0 for admin ports, and prefer AWS Systems Manager Session Manager for admin access.",
        "T-KMS-ROTATION": "Enable automatic rotation on KMS keys and monitor rotation status via AWS Config.",
        "T-IAM-KEY-AGE": "Rotate legacy IAM access keys and migrate workloads to IAM roles or temporary credentials.",
        "T-S3-PUBLIC-POLICY": "Enable S3 Block Public Access, review bucket policies, and enforce SCPs to prevent public grants.",
        "T-S3-001": "Ensure S3 Block Public Access is enabled and remove public object ACLs unless explicitly required.",
    }

    actions: List[str] = []
    actions_plain: List[str] = []
    seen = set()

    for record in steps:
        technique = record.get("technique_id")
        if not technique or technique in seen:
            continue
        findings = record.get("findings") or []
        if findings:
            tip = remediation_map.get(technique)
            if tip:
                actions.append(f"- **{technique}**: {tip}")
                actions_plain.append(f"{technique}: {tip}")
                seen.add(technique)

    services = facts.get("services", {}) or {}
    s3_buckets = services.get("s3", []) or []
    public_buckets = [bucket for bucket in s3_buckets if bucket.get("public")]
    if public_buckets and "T-S3-001" not in seen:
        tip = remediation_map.get("T-S3-001")
        if tip:
            actions.append(f"- **T-S3-001**: {tip}")
            actions_plain.append(f"T-S3-001: {tip}")

    if not actions:
        actions.append("- No immediate remediation actions identified from this run.")
        actions_plain.append("No immediate remediation actions identified.")

    remediation_markdown = "## Remediation\n" + "\n".join(actions)
    remediation_plain = "\n".join(actions_plain)
    return remediation_markdown, remediation_plain


def _summarize_events(events: Sequence[dict], steps: List[Dict[str, Any]]) -> str:
    if not events:
        return "No events recorded for this run."

    counter = Counter((record.get("status") or record.get("phase") or "unknown") for record in steps)

    lines = ["### Step Outcomes"]
    if counter:
        for status, count in sorted(counter.items()):
            lines.append(f"- {status}: {count}")
    else:
        lines.append("- No step-level telemetry captured.")

    final_status = "unknown"
    final_steps = next((event for event in reversed(events) if event.get("payload", {}).get("event_type") == "run.completed"), None)
    if final_steps:
        final_status = final_steps.get("payload", {}).get("status", final_status)

    lines.append(f"\nFinal status: **{final_status}** (steps: **{len(steps)}**)" if steps else f"\nFinal status: **{final_status}**")
    return "\n".join(lines)


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
