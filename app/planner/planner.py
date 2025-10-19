import logging
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import ValidationError

from app.planner.schema import Runbook, RunbookStep, TechniqueSpec

logger = logging.getLogger(__name__)

CATALOG_DIR = Path(__file__).resolve().parent.parent.parent / "catalog" / "techniques"

_TECHNIQUE_CACHE: Dict[str, TechniqueSpec] = {}
_CATALOG_SIGNATURE: Optional[tuple[tuple[str, int], ...]] = None


def _catalog_signature() -> tuple[tuple[str, int], ...]:
    if not CATALOG_DIR.exists():
        return ()

    signature: list[tuple[str, int]] = []
    for path in sorted(CATALOG_DIR.glob("*.y*ml")):
        try:
            signature.append((str(path), path.stat().st_mtime_ns))
        except OSError as exc:
            logger.warning("Failed to stat catalog file %s: %s", path, exc)
    return tuple(signature)


def _load_catalog_files() -> Dict[str, TechniqueSpec]:
    techniques: Dict[str, TechniqueSpec] = {}
    if not CATALOG_DIR.exists():
        logger.warning("Technique catalog directory %s does not exist.", CATALOG_DIR)
        return techniques

    for path in sorted(CATALOG_DIR.glob("*.y*ml")):
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError) as exc:
            logger.error("Failed to load technique file %s: %s", path, exc)
            continue

        try:
            spec = TechniqueSpec(**data)
        except ValidationError as exc:
            logger.error("Technique spec validation failed for %s: %s", path, exc)
            continue

        techniques[spec.id] = spec

    logger.debug("Loaded %s technique definitions from catalog", len(techniques))
    return techniques


def _load_techniques() -> Dict[str, TechniqueSpec]:
    global _TECHNIQUE_CACHE, _CATALOG_SIGNATURE

    signature = _catalog_signature()
    if _CATALOG_SIGNATURE != signature:
        _TECHNIQUE_CACHE = _load_catalog_files()
        _CATALOG_SIGNATURE = signature
    return _TECHNIQUE_CACHE


def get_technique_spec(technique_id: str) -> Optional[TechniqueSpec]:
    return _load_techniques().get(technique_id)


def _services_present(facts: Dict[str, Any]) -> Dict[str, Any]:
    return facts.get("services", {}) or {}


def _requirements_met(
    spec: TechniqueSpec,
    facts: Dict[str, Any],
    *,
    context: Optional[Dict[str, Any]] = None,
) -> bool:
    requires = spec.requires or {}
    services_required = requires.get("services") or []
    if services_required:
        services = _services_present(facts)
        for service in services_required:
            value = services.get(service)
            if service not in services or value in (None, [], False):
                return False

    predicates = requires.get("predicates") or []
    for predicate in predicates:
        try:
            predicate_ok = _evaluate_predicate(predicate, facts, context or {})
        except ValueError as exc:
            logger.error(
                "Technique %s predicate '%s' evaluation error: %s",
                spec.id,
                predicate,
                exc,
            )
            return False
        if not predicate_ok:
            logger.debug(
                "Technique %s predicate '%s' not satisfied with context %s",
                spec.id,
                predicate,
                context,
            )
            return False

    return True


def _evaluate_predicate(expression: str, facts: Dict[str, Any], context: Dict[str, Any]) -> bool:
    expr = (expression or "").strip()
    if not expr:
        return True

    for operator in (" not in ", " in ", "==", "!=", ">=", "<=", ">", "<"):
        if operator in expr:
            left, right = expr.split(operator, 1)
            left_value = _resolve_value(left.strip(), facts, context)
            right_value = _resolve_value(right.strip(), facts, context)
            op = operator.strip()

            try:
                if op == "in":
                    if right_value is None:
                        return False
                    return left_value in right_value  # type: ignore[operator]
                if op == "not in":
                    if right_value is None:
                        return True
                    return left_value not in right_value  # type: ignore[operator]
                if op == "==":
                    return left_value == right_value
                if op == "!=":
                    return left_value != right_value
                if op == ">":
                    return left_value > right_value  # type: ignore[operator]
                if op == ">=":
                    return left_value >= right_value  # type: ignore[operator]
                if op == "<":
                    return left_value < right_value  # type: ignore[operator]
                if op == "<=":
                    return left_value <= right_value  # type: ignore[operator]
            except TypeError:
                return False

    raise ValueError(f"Unsupported predicate expression '{expression}'")


def _resolve_value(token: str, facts: Dict[str, Any], context: Dict[str, Any]) -> Any:
    normalized = token.strip()
    lower = normalized.lower()
    if lower in {"true", "false"}:
        return lower == "true"
    if lower in {"null", "none"}:
        return None

    if (normalized.startswith("\"") and normalized.endswith("\"")) or (
        normalized.startswith("'") and normalized.endswith("'")
    ):
        return normalized[1:-1]

    try:
        if "." in normalized:
            return float(normalized)
        return int(normalized)
    except ValueError:
        pass

    path_parts = normalized.split(".")
    head = path_parts[0]

    if head in context:
        value: Any = context[head]
    else:
        value = facts.get(head)

    for part in path_parts[1:]:
        if isinstance(value, dict):
            value = value.get(part)
        elif isinstance(value, list):
            try:
                index = int(part)
            except ValueError:
                return None
            if index < 0 or index >= len(value):
                return None
            value = value[index]
        else:
            return None

    return value


def _merge_params(spec: TechniqueSpec, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    if spec.params:
        for key, value in spec.params.items():
            if isinstance(value, dict) and "default" in value:
                merged[key] = value["default"]
    if overrides:
        merged.update({k: v for k, v in overrides.items() if v is not None})
    return merged


def plan(facts: Dict[str, Any], goals: Optional[str] = None) -> Runbook:
    """Construct a runbook of techniques based on observed facts."""

    runbook = Runbook(goals=goals)
    techniques = _load_techniques()
    services = _services_present(facts)

    # Prioritize public S3 access simulations.
    s3_spec = techniques.get("T-S3-001")
    if s3_spec:
        for bucket in services.get("s3", []) or []:
            context = {"bucket": bucket}
            if not _requirements_met(s3_spec, facts, context=context):
                continue
            params = _merge_params(
                s3_spec,
                {"bucket": bucket.get("name")},
            )
            runbook.add_step(RunbookStep(technique_id=s3_spec.id, params=params))

    def _enqueue_if_applicable(technique_id: str) -> None:
        spec = techniques.get(technique_id)
        if not spec:
            logger.debug("Technique %s not found in catalog.", technique_id)
            return
        if not _requirements_met(spec, facts):
            logger.debug("Technique %s requirements not met.", technique_id)
            return
        params = _merge_params(spec)
        runbook.add_step(RunbookStep(technique_id=technique_id, params=params))

    _enqueue_if_applicable("T-S3-PUBLIC-POLICY")
    _enqueue_if_applicable("T-EC2-SG-OPEN")
    _enqueue_if_applicable("T-IAM-KEY-AGE")
    _enqueue_if_applicable("T-KMS-ROTATION")
    _enqueue_if_applicable("T-IAM-ENUM")
    _enqueue_if_applicable("T-ECR-ENUM")

    return runbook
