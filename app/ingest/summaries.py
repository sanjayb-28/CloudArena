"""Summary helpers for normalized findings by technique."""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from app.planner.planner import get_technique_spec

SummaryFunc = Callable[[str, List[Dict[str, object]]], str]


def _generic_summary(technique_id: str, findings: List[Dict[str, object]]) -> str:
    count = len(findings)
    return f"{count} findings detected" if count else "No findings detected"


def _ec2_sg_open_summary(technique_id: str, findings: List[Dict[str, object]]) -> str:
    if not findings:
        return "No findings detected"
    ports = sorted(
        {
            finding.get("evidence", {}).get("from_port")
            for finding in findings
            if isinstance(finding.get("evidence"), dict)
        }
    )
    port_list = ", ".join(str(port) for port in ports if port) or "various ports"
    return f"{len(findings)} security groups allow 0.0.0.0/0 (ports: {port_list})"


def _s3_public_policy_summary(technique_id: str, findings: List[Dict[str, object]]) -> str:
    if not findings:
        return "No findings detected"
    buckets = [finding.get("resource") for finding in findings if finding.get("resource")]
    bucket_list = ", ".join(buckets[:3]) if buckets else "multiple buckets"
    more = "" if len(buckets) <= 3 else f" (+{len(buckets) - 3} more)"
    return f"{len(findings)} buckets with public access: {bucket_list}{more}"


def _iam_key_age_summary(technique_id: str, findings: List[Dict[str, object]]) -> str:
    if not findings:
        return "No findings detected"
    max_age = max((finding.get("evidence", {}).get("age_days", 0) for finding in findings), default=0)
    return f"{len(findings)} IAM access keys older than 90 days (oldest {max_age} days)"


def _kms_rotation_summary(technique_id: str, findings: List[Dict[str, object]]) -> str:
    if not findings:
        return "No findings detected"
    return f"{len(findings)} KMS keys with rotation disabled"


SUMMARY_RULES: Dict[str, SummaryFunc] = {
    "generic": _generic_summary,
    "ec2_sg_open": _ec2_sg_open_summary,
    "s3_public_policy": _s3_public_policy_summary,
    "iam_key_age": _iam_key_age_summary,
    "kms_rotation": _kms_rotation_summary,
}

DEFAULT_RULE = "generic"


def summarize_findings(technique_id: Optional[str], findings: List[Dict[str, object]]) -> str:
    if not technique_id:
        return SUMMARY_RULES[DEFAULT_RULE]("unknown", findings)

    spec = get_technique_spec(technique_id)
    rule_name = None
    if spec and spec.report:
        rule_name = spec.report.get("summary_rule")

    summary_func = SUMMARY_RULES.get(rule_name or DEFAULT_RULE, SUMMARY_RULES[DEFAULT_RULE])
    return summary_func(technique_id, findings)


def register_summary(rule_name: str, func: SummaryFunc) -> None:
    """Register a new summary function keyed by catalog metadata."""

    if not rule_name:
        raise ValueError("Summary rule name must be provided")
    if rule_name in SUMMARY_RULES:
        raise ValueError(f"Summary rule '{rule_name}' is already registered")
    SUMMARY_RULES[rule_name] = func


def available_summaries() -> List[str]:
    """Return sorted summary identifiers for discovery and documentation."""

    return sorted(SUMMARY_RULES.keys())
