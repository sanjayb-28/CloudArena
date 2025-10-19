"""Normalization helpers for worker step results before they are persisted."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.ingest.summaries import summarize_findings

SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3}


def coerce_finding(finding: Any) -> Dict[str, Any]:
    """Ensure a finding record is represented as a dictionary."""
    if isinstance(finding, dict):
        return finding
    return {"summary": str(finding)}


def max_severity(findings: List[Dict[str, Any]], default: Optional[str]) -> Optional[str]:
    """Return the most severe level observed across findings."""
    highest = (default or "informational").lower()
    for finding in findings:
        candidate = (finding.get("severity") or highest).lower()
        if SEVERITY_ORDER.get(candidate, 0) > SEVERITY_ORDER.get(highest, 0):
            highest = candidate
    return highest


def normalize_result(
    technique_id: Optional[str],
    result: Dict[str, Any],
    default_severity: Optional[str],
) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Normalize adapter results for downstream storage and reporting."""
    raw_findings = result.get("findings") or []
    findings = [coerce_finding(item) for item in raw_findings]
    summary = result.get("summary")
    details = result.get("details") if isinstance(result.get("details"), dict) else None
    artifacts: List[Dict[str, Any]] = []

    result_severity = result.get("severity")
    baseline_severity = result_severity or default_severity or "informational"
    effective_severity = max_severity(findings, baseline_severity)

    if findings:
        summary = summary or summarize_findings(technique_id, findings)
        if details is None:
            details = {"findings": findings[:5]}
        artifacts.append({"type": "finding_count", "uri": str(len(findings))})
    elif result.get("stdout"):
        summary = summary or str(result["stdout"])[:200]
    else:
        summary = summary or "No findings detected"

    return effective_severity, summary, details, artifacts
