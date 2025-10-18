"""Adapter for invoking Stratus Red Team simulations."""

import subprocess
from typing import Any, Dict, Optional


STRATUS_COMMAND = "stratus"
TECHNIQUE_MAP = {
    "stratus.aws.s3.public_read_sim": "aws/exfiltration/s3/public-read-acl",
}


def _build_command(technique_id: str, bucket: Optional[str]) -> list[str]:
    mapped = TECHNIQUE_MAP.get(technique_id)
    if not mapped:
        raise ValueError(f"Unsupported Stratus technique '{technique_id}'")

    command = [STRATUS_COMMAND, "detonate", mapped, "--cleanup"]
    if bucket:
        command.extend(["--bucket", bucket])

    return command


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

    bucket = params.get("bucket")
    command = _build_command(technique_id, bucket)

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        return {"ok": False, "error": f"Stratus CLI not found: {exc}"}
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "error": f"Stratus execution timed out: {exc}"}

    result = {"ok": completed.returncode == 0}
    if completed.stdout:
        result["stdout"] = completed.stdout
    if completed.stderr:
        result["stderr"] = completed.stderr

    return result
