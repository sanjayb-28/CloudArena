"""Adapter for invoking Stratus Red Team detonations."""

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Set

import yaml

COMMAND = "stratus"
MAP_PATH = Path(__file__).resolve().parents[2] / "catalog" / "techniques_map.yaml"

try:
    if MAP_PATH.exists():
        with MAP_PATH.open("r", encoding="utf-8") as handle:
            _MAP_DATA = yaml.safe_load(handle) or {}
            if not isinstance(_MAP_DATA, dict):
                raise ValueError("techniques_map.yaml must define a mapping")
    else:
        _MAP_DATA = {}
except (OSError, yaml.YAMLError, ValueError) as exc:
    raise RuntimeError(f"Unable to load Stratus technique map: {exc}") from exc


def _discover_stratus_adapters() -> Set[str]:
    techniques_dir = Path(__file__).resolve().parents[2] / "catalog" / "techniques"
    identifiers: Set[str] = set()
    if not techniques_dir.exists():
        return identifiers

    for path in techniques_dir.glob("*.y*ml"):
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError):
            continue

        impl = data.get("impl") or {}
        adapter = impl.get("adapter")
        if isinstance(adapter, str) and adapter.startswith("stratus."):
            identifiers.add(adapter)
    return identifiers


_MISSING_MAPPINGS = sorted(adapter for adapter in _discover_stratus_adapters() if adapter not in _MAP_DATA)
if _MISSING_MAPPINGS:
    raise RuntimeError(
        "Missing Stratus CLI mappings for: " + ", ".join(_MISSING_MAPPINGS)
    )


def _resolve_technique(identifier: str) -> str:
    mapped = _MAP_DATA.get(identifier)
    if not mapped:
        raise ValueError(f"Unsupported Stratus technique '{identifier}'")
    return mapped


def run_stratus(
    technique_id: str,
    adapter: str,
    params: Dict[str, Any],
    *,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """Execute a Stratus technique via the CLI."""

    if adapter != "stratus":
        raise ValueError(f"Unsupported adapter '{adapter}' for Stratus runner")

    resolved = _resolve_technique(technique_id)

    bucket = params.get("bucket")
    command = [COMMAND, "detonate", resolved, "--cleanup"]
    if bucket:
        command.extend(["--bucket", bucket])

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return {
            "ok": False,
            "error": "stratus not installed",
            "summary": "Stratus CLI is not available on worker",
            "severity": "high",
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "error": f"Stratus execution timed out: {exc}",
            "summary": "Stratus technique timed out",
            "severity": "high",
        }

    result = {"ok": completed.returncode == 0}
    if completed.stdout:
        result["stdout"] = completed.stdout
    if completed.stderr:
        result["stderr"] = completed.stderr

    if result["ok"]:
        result.setdefault("summary", f"Executed Stratus technique {resolved}")
        result.setdefault("severity", "medium")
    else:
        result.setdefault("error", "Stratus command failed")
        result.setdefault("summary", "Stratus technique execution failed")
        result.setdefault("severity", "high")

    return result
