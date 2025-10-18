"""Adapter for invoking Stratus Red Team simulations."""

import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

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
        return {"ok": False, "error": "stratus not installed"}
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "error": f"Stratus execution timed out: {exc}"} 

    result = {"ok": completed.returncode == 0}
    if completed.stdout:
        result["stdout"] = completed.stdout
    if completed.stderr:
        result["stderr"] = completed.stderr

    if not result["ok"]:
        result.setdefault("error", "Stratus command failed")

    return result
