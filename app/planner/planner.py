import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

import yaml
from pydantic import ValidationError

from app.planner.schema import Runbook, RunbookStep, TechniqueSpec
from app.planner import rules as planner_rules

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


def get_technique_catalog() -> Dict[str, TechniqueSpec]:
    """Return a copy of the loaded technique catalog keyed by identifier."""

    return dict(_load_techniques())


def list_technique_specs() -> List[TechniqueSpec]:
    """Return all registered technique specs in catalog order."""

    return list(_load_techniques().values())


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
            predicate_ok = evaluate_predicate(predicate, facts, context or {})
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


def evaluate_predicate(expression: str, facts: Dict[str, Any], context: Dict[str, Any]) -> bool:
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
    techniques = get_technique_catalog()
    account_id = facts.get("account")
    region = facts.get("region")

    goal_tokens = _tokenize_goals(goals)

    common_params = {
        key: value
        for key, value in {
            "account": account_id,
            "region": region,
        }.items()
        if value is not None
    }

    steps_with_priority: list[tuple[int, RunbookStep, str]] = []
    fallback_candidates: list[tuple[int, RunbookStep, str]] = []

    for spec in sorted(techniques.values(), key=lambda item: item.id):
        planner_config = spec.planner or {}
        if not planner_config.get("auto"):
            continue

        rule_name = planner_config.get("rule")
        rule = planner_rules.get_rule(rule_name)

        base_params = {**common_params}
        static_params = planner_config.get("params") or {}
        if static_params:
            base_params.update(static_params)

        generated_params = rule(spec, facts, common_params, _requirements_met)
        if not generated_params:
            continue

        matches_goal = _technique_matches_goal(spec, planner_config, goal_tokens)
        priority = int(planner_config.get("priority", 100))
        for overrides in generated_params:
            combined: Dict[str, Any] = {**base_params}
            if overrides:
                combined.update({k: v for k, v in overrides.items() if v is not None})
            params = _merge_params(spec, combined)
            step = RunbookStep(technique_id=spec.id, params=params)
            candidate = (priority, step, spec.id)
            fallback_candidates.append(candidate)
            if not goal_tokens or matches_goal:
                steps_with_priority.append(candidate)

    selected = steps_with_priority
    if goal_tokens and not selected:
        logger.debug(
            "No techniques matched goals %s; falling back to all auto-enabled techniques.",
            sorted(goal_tokens),
        )
        selected = fallback_candidates

    for _, step, _ in sorted(selected, key=lambda item: (item[0], item[2])):
        runbook.add_step(step)

    return runbook


def _tokenize_goals(goals: Optional[str]) -> Set[str]:
    if not goals:
        return set()
    return {token for token in re.findall(r"[a-z0-9]+", goals.lower()) if len(token) >= 2}


def _technique_matches_goal(
    spec: TechniqueSpec,
    planner_config: Dict[str, Any],
    goal_tokens: Set[str],
) -> bool:
    if not goal_tokens:
        return True

    if planner_config.get("always"):
        return True

    if planner_config.get("goal_optional"):
        return True

    tag_candidates: Set[str] = set()
    tag_candidates.update(_tokenize_sequence(spec.goal_tags))
    tag_candidates.update(_tokenize_sequence(planner_config.get("goal_tags")))

    if not tag_candidates:
        return False

    return bool(tag_candidates & goal_tokens)


def _tokenize_sequence(values: Optional[Sequence[Any]]) -> Set[str]:
    tokens: Set[str] = set()
    if not values:
        return tokens
    for value in values:
        if value is None:
            continue
        tokens.update(token for token in re.findall(r"[a-z0-9]+", str(value).lower()) if token)
    return tokens
