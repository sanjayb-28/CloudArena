from __future__ import annotations

import json
from collections import Counter
import logging
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from app.ingest import SEVERITY_ORDER
from app.planner import evaluate_predicate
from app.remediations import get_remediation, list_remediations
from app.settings import get_settings


logger = logging.getLogger(__name__)


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
        except Exception as exc:
            logger.exception("Gemini report rendering failed: %s", exc)

    return _render_static_markdown(facts, event_dicts)


def _render_static_markdown(facts: dict, events: Sequence[dict]) -> str:
    summary_md, _, findings_block, remediation_md, _, step_records = _prepare_sections(facts, events)

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
        findings_block,
        "",
        remediation_md,
        "",
        "## Run Telemetry",
        _summarize_events(events, step_records),
    ]

    return "\n".join(sections)


def _render_with_gemini(facts: dict, events: Sequence[dict]) -> str:
    summary_md, summary_plain, findings_block, remediation_md, remediation_plain, step_records = _prepare_sections(
        facts, events
    )

    settings = get_settings()
    prompt = f"""Rewrite the following CloudArena security exercise summary in concise executive prose.\n\nSummary:\n{summary_plain}\n\nRecommended remediation actions:\n{remediation_plain}\n\nReturn two sections:\n1. Executive Summary (2-3 sentences)\n2. Remediation Recommendations (bullet list)"""

    try:
        import google.generativeai as genai

        genai.configure(api_key=settings.gemini_api_key, transport="rest")
        model_candidates = [
            "models/gemini-2.5-flash",
            "models/gemini-flash-latest",
            "models/gemini-2.0-flash",
            "models/gemini-pro-latest",
        ]
        response = None
        last_error: Exception | None = None
        for model_name in model_candidates:
            try:
                model = genai.GenerativeModel(model_name=model_name)
                response = model.generate_content(prompt)
                logger.info("Gemini report generated with %s", model_name)
                break
            except Exception as model_exc:
                last_error = model_exc
                logger.warning("Gemini model %s failed: %s", model_name, model_exc)
        if response is None or not response.text:
            if last_error is not None:
                raise last_error
            raise ValueError("Empty response from Gemini")
        generated = response.text.strip()
    except Exception as exc: 
        raise RuntimeError(f"Gemini generation failed: {exc}") from exc

    logger.info("Generated Gemini executive summary for report")

    sections = [
        "# CloudArena Run Report",
        "## Executive Summary (Gemini)",
        generated,
        "",
        findings_block,
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
    findings_block = _build_findings_block(steps)
    remediation_md, remediation_plain = _build_remediation_section(facts, steps)
    return summary_md, summary_plain, findings_block, remediation_md, remediation_plain, steps


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
        collected_findings: Optional[List[Dict[str, Any]]] = None
        if details:
            record["details"] = details
            findings = details.get("findings") if isinstance(details, dict) else None
            if isinstance(findings, list):
                collected_findings = findings
        result = payload.get("result")
        if collected_findings is None and isinstance(result, dict):
            findings = result.get("findings")
            if isinstance(findings, list):
                collected_findings = findings
        if collected_findings is None:
            findings = event.get("findings")
            if isinstance(findings, list):
                collected_findings = findings
        if collected_findings is not None:
            record["findings"] = collected_findings
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
        summary_lines.extend(entry for entry in top_risk_entries if entry.strip())
    else:
        summary_lines.append("### Top Risks")
        summary_lines.append("- No significant risks detected.")

    summary_markdown = "\n".join(summary_lines)
    summary_plain = "\n".join(line.lstrip("- ") for line in summary_lines if line.startswith("- "))
    return summary_markdown, summary_plain.strip()


def _default_summary(record: Dict[str, Any]) -> str:
    findings = record.get("findings") or []
    if findings:
        return f"{len(findings)} findings detected"
    return "No findings reported"


def _build_findings_block(steps: List[Dict[str, Any]]) -> str:
    if not steps:
        return "## Findings\nNo findings recorded."

    lines: List[str] = ["## Findings"]
    first_entry = True

    for record in steps:
        technique = record.get("technique_id") or "unknown"
        findings = record.get("findings") or []
        header_severity = _format_severity(record.get("severity"))

        if not first_entry:
            lines.append("")
        first_entry = False

        if findings:
            lines.append(f"### {technique}")
            for finding in findings:
                severity = _format_severity(finding.get("severity") or record.get("severity"))
                resource = finding.get("resource") or record.get("resource") or "n/a"
                issue = finding.get("issue") or record.get("summary") or _default_summary(record)
                evidence = _format_evidence(finding.get("evidence"))
                lines.extend(
                    [
                        f"- **Severity:** {severity}",
                        f"    - **Resource:** `{resource}`",
                        f"    - **Issue:** {issue}",
                        f"    - **Evidence:** {evidence}",
                    ]
                )
        else:
            lines.append(f"### {technique}")
            resource = record.get("resource") or "n/a"
            issue = record.get("summary") or _default_summary(record)
            evidence = _format_evidence(record.get("details"))
            lines.extend(
                [
                    f"- **Severity:** {header_severity}",
                    f"    - **Resource:** `{resource}`",
                    f"    - **Issue:** {issue}",
                    f"    - **Evidence:** {evidence}",
                ]
            )

    return "\n".join(lines)


def _format_severity(value: Optional[str]) -> str:
    if not value:
        return "Informational"
    return str(value).strip().title()


def _format_evidence(evidence: Any, limit: int = 140) -> str:
    if not evidence:
        return "n/a"
    if isinstance(evidence, str):
        text = evidence.strip()
    elif isinstance(evidence, dict):
        items: List[str] = []
        for index, (key, value) in enumerate(evidence.items()):
            if index >= 5:
                items.append("...")
                break
            items.append(f"{key}={_shorten_evidence_value(value)}")
        text = ", ".join(items)
    elif isinstance(evidence, (list, tuple, set)):
        parts = [_shorten_evidence_value(item) for item in list(evidence)[:5]]
        if len(parts) < len(evidence):
            parts.append("...")
        text = ", ".join(parts)
    else:
        text = str(evidence)

    text = text.strip()
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    text = text.replace("\n", " ")
    return text or "n/a"


def _shorten_evidence_value(value: Any, max_len: int = 60) -> str:
    if isinstance(value, (dict, list, tuple, set)):
        try:
            text = json.dumps(value, default=str)
        except TypeError:
            text = str(value)
    else:
        text = str(value)

    text = text.replace("\n", " ")
    if len(text) > max_len:
        text = text[: max_len - 3].rstrip() + "..."
    return text


def _build_remediation_section(facts: dict, steps: List[Dict[str, Any]]) -> Tuple[str, str]:
    actions: List[str] = []
    actions_plain: List[str] = []
    seen = set()

    for record in steps:
        technique = record.get("technique_id")
        if not technique or technique in seen:
            continue
        findings = record.get("findings") or []
        if findings:
            guide = get_remediation(technique)
            if guide:
                message = guide.merged_summary()
                actions.append(f"- **{technique}**: {message}")
                actions_plain.append(f"{technique}: {message}")
                seen.add(technique)

    services = facts.get("services", {}) or {}
    s3_buckets = services.get("s3", []) or []
    public_buckets = [bucket for bucket in s3_buckets if bucket.get("public")]

    condition_context = {
        "public_s3_buckets": bool(public_buckets),
        "public_s3_bucket_count": len(public_buckets),
        "public_s3_bucket_names": [bucket.get("name") for bucket in public_buckets if bucket.get("name")],
    }

    for guide in list_remediations():
        if guide.id in seen or not guide.conditions:
            continue
        if _conditions_match(guide.conditions, facts, condition_context):
            message = guide.merged_summary()
            actions.append(f"- **{guide.id}**: {message}")
            actions_plain.append(f"{guide.id}: {message}")
            seen.add(guide.id)

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




def _conditions_match(conditions: Dict[str, Any], facts: dict, context: Dict[str, Any]) -> bool:
    if not conditions:
        return False

    services = conditions.get("services")
    if services:
        observed = facts.get("services", {}) or {}
        for service in services:
            value = observed.get(service)
            if value in (None, [], False):
                return False

    predicates = conditions.get("predicates")
    if predicates:
        for predicate in predicates:
            try:
                if not evaluate_predicate(predicate, facts, context):
                    return False
            except ValueError:
                return False

    for key, expected in conditions.items():
        if key in {"services", "predicates"}:
            continue
        value = _resolve_condition_value(key, facts, context)
        if isinstance(expected, bool):
            if bool(value) != expected:
                return False
        elif expected is None:
            if value is not None:
                return False
        else:
            if value != expected:
                return False

    return True


def _resolve_condition_value(path: str, facts: dict, context: Dict[str, Any]) -> Any:
    if not path:
        return None
    if path in context:
        return context[path]

    parts = path.split(".")
    current: Any = facts
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                index = int(part)
            except ValueError:
                return None
            if index < 0 or index >= len(current):
                return None
            current = current[index]
        else:
            return None
    return current
