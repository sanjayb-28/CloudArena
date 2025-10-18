"""Adapters for invoking CloudArena SDK techniques via AWS SDKs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def _list_iam_roles() -> List[str]:
    iam = boto3.client("iam")
    roles: List[str] = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            name = role.get("RoleName")
            if name:
                roles.append(name)
    return roles


def _list_ecr_repositories() -> List[str]:
    ecr = boto3.client("ecr")
    repos: List[str] = []
    paginator = ecr.get_paginator("describe_repositories")
    for page in paginator.paginate():
        for repo in page.get("repositories", []):
            name = repo.get("repositoryName")
            if name:
                repos.append(name)
    return repos


def _audit_security_groups() -> List[Dict[str, Any]]:
    ec2 = boto3.client("ec2")
    findings: List[Dict[str, Any]] = []
    paginator = ec2.get_paginator("describe_security_groups")
    common_ports = {22, 3389, 80, 443}
    for page in paginator.paginate():
        for sg in page.get("SecurityGroups", []):
            group_id = sg.get("GroupId")
            group_name = sg.get("GroupName")
            for permission in sg.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                ip_protocol = permission.get("IpProtocol")

                # Determine whether the rule covers interesting ports
                relevant = True
                if from_port is not None and to_port is not None:
                    relevant = any(from_port <= port <= to_port for port in common_ports)
                if not relevant:
                    continue

                for ip_range in permission.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        findings.append(
                            {
                                "security_group_id": group_id,
                                "security_group_name": group_name,
                                "protocol": ip_protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "description": ip_range.get("Description"),
                            }
                        )
    return findings


def _audit_kms_rotation() -> List[Dict[str, Any]]:
    kms = boto3.client("kms")
    findings: List[Dict[str, Any]] = []
    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for key in page.get("Keys", []):
            key_id = key.get("KeyId")
            if not key_id:
                continue
            try:
                rotation = kms.get_key_rotation_status(KeyId=key_id)
            except ClientError as exc:
                findings.append(
                    {
                        "key_id": key_id,
                        "issue": "rotation_status_check_failed",
                        "error": exc.response["Error"].get("Message", str(exc)),
                    }
                )
                continue
            if not rotation.get("KeyRotationEnabled"):
                findings.append({"key_id": key_id, "issue": "rotation_disabled"})
    return findings


def _audit_iam_key_age() -> List[Dict[str, Any]]:
    iam = boto3.client("iam")
    findings: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc)

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user.get("UserName")
            if not user_name:
                continue
            access_keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
            for key in access_keys:
                key_id = key.get("AccessKeyId")
                create_date = key.get("CreateDate")
                if create_date is None:
                    continue
                age_days = (now - create_date).days
                if age_days > 90:
                    findings.append({"user": user_name, "access_key_id": key_id, "age_days": age_days})
    return findings


def _audit_s3_public_policies() -> List[Dict[str, Any]]:
    s3 = boto3.client("s3")
    findings: List[Dict[str, Any]] = []
    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket.get("Name")
        if not name:
            continue
        try:
            response = s3.get_bucket_policy(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"].get("Code") in {"NoSuchBucketPolicy", "NoSuchBucket", "AccessDenied"}:
                continue
            raise
        policy_str = response.get("Policy")
        if not policy_str:
            continue
        try:
            policy_doc = json.loads(policy_str)
        except json.JSONDecodeError:
            findings.append({"bucket": name, "issue": "policy_parse_error"})
            continue
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal")
            principal_public = False
            if principal == "*":
                principal_public = True
            elif isinstance(principal, dict):
                principal_public = any(
                    value == "*" or (isinstance(value, list) and "*" in value) for value in principal.values()
                )

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            allows_get = any(action in {"s3:GetObject", "s3:*"} for action in actions)

            if principal_public and allows_get:
                findings.append({"bucket": name, "public": True, "statement": statement})
                break
    return findings


def run_sdk(technique_id: str, adapter: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a technique implemented via AWS SDK primitives."""

    if adapter != "sdk":
        raise ValueError(f"Unsupported adapter '{adapter}' for SDK runner")

    try:
        if technique_id == "sdk.iam.enum":
            roles = _list_iam_roles()
            return {"ok": True, "roles": roles}

        if technique_id == "sdk.ecr.enum":
            repos = _list_ecr_repositories()
            return {"ok": True, "repositories": repos}

        if technique_id == "sdk.ec2.sg_audit":
            return {"ok": True, "findings": _audit_security_groups()}

        if technique_id == "sdk.kms.rotation_audit":
            return {"ok": True, "findings": _audit_kms_rotation()}

        if technique_id == "sdk.iam.key_age":
            return {"ok": True, "findings": _audit_iam_key_age()}

        if technique_id == "sdk.s3.public_policy_audit":
            return {"ok": True, "findings": _audit_s3_public_policies()}
    except (BotoCoreError, ClientError) as exc:
        return {"ok": False, "error": str(exc)}

    raise ValueError(f"Unsupported SDK technique '{technique_id}'")
