import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml  # type: ignore[import]

CATALOG_DIR = Path(__file__).resolve().parent.parent.parent / "catalog" / "remediations"

logger = logging.getLogger(__name__)


@dataclass
class RemediationGuide:
    """Structured remediation guidance loaded from the catalog."""

    id: str
    summary: str
    actions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)

    def merged_summary(self) -> str:
        """Return a single-line summary suitable for reports."""
        if self.actions:
            action_text = "; ".join(action.strip() for action in self.actions if action)
            if action_text:
                return f"{self.summary.strip()} Actions: {action_text}."
        return self.summary.strip()


_GUIDE_CACHE: Dict[str, RemediationGuide] = {}
_CATALOG_SIGNATURE: Optional[Tuple[Tuple[str, int], ...]] = None


def _catalog_signature() -> Tuple[Tuple[str, int], ...]:
    if not CATALOG_DIR.exists():
        return ()

    signature: List[Tuple[str, int]] = []
    for path in sorted(CATALOG_DIR.glob("*")):
        if not path.is_file():
            continue
        try:
            signature.append((str(path), path.stat().st_mtime_ns))
        except OSError as exc:  # pragma: no cover - filesystem edge case
            logger.warning("Unable to stat remediation file %s: %s", path, exc)
    return tuple(signature)


def _load_guides() -> Dict[str, RemediationGuide]:
    guides: Dict[str, RemediationGuide] = {}
    if not CATALOG_DIR.exists():
        logger.debug("Remediation catalog directory %s does not exist.", CATALOG_DIR)
        return guides

    for path in sorted(CATALOG_DIR.glob("*")):
        if path.suffix.lower() in {".yaml", ".yml"}:
            try:
                with path.open("r", encoding="utf-8") as handle:
                    data = yaml.safe_load(handle) or {}
            except (OSError, yaml.YAMLError) as exc:
                logger.error("Failed to load remediation YAML %s: %s", path, exc)
                continue
            guide = _guide_from_mapping(path, data)
        elif path.suffix.lower() in {".md", ".txt"}:
            try:
                summary = path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                logger.error("Failed to load remediation text %s: %s", path, exc)
                continue
            guide = RemediationGuide(id=path.stem, summary=summary)
        else:
            logger.debug("Skipping remediation file %s with unsupported extension", path)
            continue

        if guide and guide.id:
            guides[guide.id] = guide

    logger.debug("Loaded %s remediation guides", len(guides))
    return guides


def _guide_from_mapping(path: Path, data: Dict[str, Any]) -> RemediationGuide:
    identifier = str(data.get("id") or path.stem)
    summary = str(data.get("summary") or data.get("recommendation") or "Review configuration and apply best practices.")

    actions_value = data.get("actions")
    if isinstance(actions_value, Iterable) and not isinstance(actions_value, (str, bytes)):
        actions = [str(item) for item in actions_value if str(item).strip()]
    else:
        actions = []

    references_value = data.get("references")
    if isinstance(references_value, Iterable) and not isinstance(references_value, (str, bytes)):
        references = [str(item) for item in references_value if str(item).strip()]
    else:
        references = []

    conditions_value = data.get("conditions")
    if isinstance(conditions_value, dict):
        conditions = {str(key): value for key, value in conditions_value.items()}
    else:
        conditions = {}

    return RemediationGuide(
        id=identifier,
        summary=summary,
        actions=actions,
        references=references,
        conditions=conditions,
    )


def _ensure_cache() -> None:
    global _GUIDE_CACHE, _CATALOG_SIGNATURE
    signature = _catalog_signature()
    if signature != _CATALOG_SIGNATURE:
        _GUIDE_CACHE = _load_guides()
        _CATALOG_SIGNATURE = signature


def get_remediation(technique_id: str) -> Optional[RemediationGuide]:
    """Return remediation guidance for a specific technique, if available."""
    _ensure_cache()
    return _GUIDE_CACHE.get(technique_id)


def list_remediations() -> List[RemediationGuide]:
    """Return all remediation guides sorted by technique id."""
    _ensure_cache()
    return [_GUIDE_CACHE[key] for key in sorted(_GUIDE_CACHE.keys())]