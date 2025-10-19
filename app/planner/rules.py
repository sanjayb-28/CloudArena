"""Planner rules for turning catalog techniques into runbook steps."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from app.planner.schema import TechniqueSpec

RuleFunc = Callable[[TechniqueSpec, Dict[str, Any], Dict[str, Any], Callable[[TechniqueSpec, Dict[str, Any], Optional[Dict[str, Any]]], bool]], List[Dict[str, Any]]]


def simple_auto(
    spec: TechniqueSpec,
    facts: Dict[str, Any],
    common: Dict[str, Any],
    requirements_met: Callable[[TechniqueSpec, Dict[str, Any], Optional[Dict[str, Any]]], bool],
) -> List[Dict[str, Any]]:
    if not requirements_met(spec, facts):
        return []
    return [{}]


def s3_public_simulation(
    spec: TechniqueSpec,
    facts: Dict[str, Any],
    common: Dict[str, Any],
    requirements_met: Callable[[TechniqueSpec, Dict[str, Any], Optional[Dict[str, Any]]], bool],
) -> List[Dict[str, Any]]:
    services = facts.get("services", {}) or {}
    buckets = services.get("s3", []) or []
    params: List[Dict[str, Any]] = []
    for bucket in buckets:
        context = {"bucket": bucket}
        if not requirements_met(spec, facts, context=context):
            continue
        name = bucket.get("name")
        if not name:
            continue
        overrides = {
            "bucket": name,
            "public": bool(bucket.get("public")),
        }
        params.append(overrides)
    params.sort(key=lambda item: item.get("bucket", ""))
    return params


def s3_policy_audit(
    spec: TechniqueSpec,
    facts: Dict[str, Any],
    common: Dict[str, Any],
    requirements_met: Callable[[TechniqueSpec, Dict[str, Any], Optional[Dict[str, Any]]], bool],
) -> List[Dict[str, Any]]:
    if not requirements_met(spec, facts):
        return []
    services = facts.get("services", {}) or {}
    buckets = services.get("s3", []) or []
    public = [bucket.get("name") for bucket in buckets if bucket.get("public") and bucket.get("name")]
    overrides = {
        "total_buckets": len(buckets),
        "public_bucket_count": len(public),
        "public_buckets": public,
    }
    return [overrides]


RULES: Dict[str, RuleFunc] = {
    "simple": simple_auto,
    "simple_auto": simple_auto,
    "s3_public_simulation": s3_public_simulation,
    "s3_policy_audit": s3_policy_audit,
}


def get_rule(name: Optional[str]) -> RuleFunc:
    if name and name in RULES:
        return RULES[name]
    return RULES["simple"]


def register_rule(name: str, func: RuleFunc) -> None:
    """Register a new planner rule for catalog-driven execution."""

    if not name:
        raise ValueError("Rule name must be provided")
    if name in RULES:
        raise ValueError(f"Rule '{name}' is already registered")
    RULES[name] = func


def available_rules() -> List[str]:
    """List all registered rule identifiers."""

    return sorted(RULES.keys())
