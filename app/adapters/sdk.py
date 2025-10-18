"""Adapters for invoking CloudArena SDK techniques via AWS SDKs."""

from typing import Any, Dict, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def _list_iam_roles() -> List[str]:
    iam = boto3.client("iam")

    roles: List[str] = []
    paginator = iam.get_paginator("list_roles")
    try:
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                name = role.get("RoleName")
                if name:
                    roles.append(name)
    except (BotoCoreError, ClientError):
        raise

    return roles


def _list_ecr_repositories() -> List[str]:
    ecr = boto3.client("ecr")
    repos: List[str] = []
    paginator = ecr.get_paginator("describe_repositories")
    try:
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                name = repo.get("repositoryName")
                if name:
                    repos.append(name)
    except (BotoCoreError, ClientError):
        raise

    return repos


def run_sdk(technique_id: str, adapter: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a technique implemented via AWS SDK primitives."""

    if adapter != "sdk":
        raise ValueError(f"Unsupported adapter '{adapter}' for SDK runner")

    if technique_id == "sdk.iam.enum":
        roles = _list_iam_roles()
        return {"ok": True, "roles": roles}

    if technique_id == "sdk.ecr.enum":
        repos = _list_ecr_repositories()
        return {"ok": True, "repositories": repos}

    raise ValueError(f"Unsupported SDK technique '{technique_id}'")
