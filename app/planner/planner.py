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


def plan(facts: Dict[str, Any], goals: Optional[str] = None) -> Runbook:
    """Construct a runbook of techniques based on observed facts."""

    runbook = Runbook(goals=goals)
    techniques = _load_techniques()

    services = facts.get("services", {})
    s3_facts = services.get("s3", []) or []
    for bucket in s3_facts:
        if bucket.get("public"):
            bucket_name = bucket.get("name")
            params: Dict[str, Any] = {}
            spec = techniques.get("T-S3-001")
            if spec:
                params.update(spec.params)
            if bucket_name:
                params["bucket"] = bucket_name

            step = RunbookStep(technique_id="T-S3-001", params=params)
            runbook.add_step(step)

    return runbook
