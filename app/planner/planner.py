import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import ValidationError

from app.planner.schema import Runbook, RunbookStep, TechniqueSpec

logger = logging.getLogger(__name__)

CATALOG_DIR = Path(__file__).resolve().parent.parent.parent / "catalog" / "techniques"


@lru_cache(maxsize=1)
def _load_techniques() -> Dict[str, TechniqueSpec]:
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

    return techniques


def get_technique_spec(technique_id: str) -> Optional[TechniqueSpec]:
    return _load_techniques().get(technique_id)


def _services_present(facts: Dict[str, Any]) -> Dict[str, Any]:
    return facts.get("services", {}) or {}


def _requirements_met(spec: TechniqueSpec, facts: Dict[str, Any]) -> bool:
    requires = spec.requires or {}
    services_required = requires.get("services") or []
    if services_required:
        services = _services_present(facts)
        for service in services_required:
            value = services.get(service)
            if service not in services or value in (None, [], False):
                return False

    # TODO: Evaluate predicate expressions when planner DSL is finalized.
    return True


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
    if s3_spec and _requirements_met(s3_spec, facts):
        for bucket in services.get("s3", []) or []:
            if bucket.get("public"):
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
