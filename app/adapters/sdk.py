"""Adapters for invoking CloudArena SDK techniques via AWS SDKs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.settings import get_settings


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
    admin_ports = {22, 3389}
    web_ports = {80, 443}

    for page in paginator.paginate():
        for sg in page.get("SecurityGroups", []):
            group_id = sg.get("GroupId")
            group_name = sg.get("GroupName")
            for permission in sg.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                ports = (from_port, to_port)
                for ip_range in permission.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        severity = _sg_severity(ports, admin_ports, web_ports)
                        issue = _describe_sg_issue(ports, permission.get("IpProtocol"))
                        findings.append(
                            {
                                "resource": group_id or group_name or "unknown",
                                "issue": issue,
                                "severity": severity,
                                "evidence": {
                                    "group_id": group_id,
                                    "group_name": group_name,
                                    "protocol": permission.get("IpProtocol"),
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "description": ip_range.get("Description"),
                                },
                            }
                        )
    return findings


def _sg_severity(
    ports: tuple[Optional[int], Optional[int]],
    admin_ports: set[int],
    web_ports: set[int],
) -> str:
    start, end = ports
    if start is None or end is None:
        return "medium"
    port_range = set(range(start, end + 1))
    if port_range & admin_ports:
        return "high"
    if port_range & web_ports:
        return "medium"
    return "medium"


def _describe_sg_issue(ports: tuple[Optional[int], Optional[int]], protocol: Optional[str]) -> str:
    start, end = ports
    if start is None or end is None:
        port_desc = "all ports"
    elif start == end:
        port_desc = f"port {start}"
    else:
        port_desc = f"ports {start}-{end}"
    proto = protocol or "all protocols"
    return f"Ingress from 0.0.0.0/0 on {proto} {port_desc}"


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
                        "resource": key_id,
                        "issue": "Rotation status check failed",
                        "severity": "medium",
                        "evidence": {"error": exc.response["Error"].get("Message", str(exc))},
                    }
                )
                continue
            if not rotation.get("KeyRotationEnabled"):
                findings.append(
                    {
                        "resource": key_id,
                        "issue": "KMS key rotation disabled",
                        "severity": "medium",
                        "evidence": {"rotation_enabled": False},
                    }
                )
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
                    severity = "high" if age_days > 180 else "medium"
                    findings.append(
                        {
                            "resource": f"{user_name}:{key_id}",
                            "issue": f"IAM access key age {age_days} days",
                            "severity": severity,
                            "evidence": {
                                "user": user_name,
                                "access_key_id": key_id,
                                "age_days": age_days,
                            },
                        }
                    )
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
            findings.append(
                {
                    "resource": name,
                    "issue": "Bucket policy parse error",
                    "severity": "medium",
                    "evidence": {"policy": policy_str[:200]},
                }
            )
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
                findings.append(
                    {
                        "resource": name,
                        "issue": "Bucket policy allows public s3:GetObject",
                        "severity": "medium",
                        "evidence": {"statement": statement},
                    }
                )
                break
    return findings


def run_sdk(technique_id: str, adapter: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a technique implemented via AWS SDK primitives."""

    if adapter != "sdk":
        raise ValueError(f"Unsupported adapter '{adapter}' for SDK runner")

    settings = get_settings()
    if settings.simulation_mode:
        return _simulate_sdk(technique_id)

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


def _simulate_sdk(technique_id: str) -> Dict[str, Any]:
    if technique_id == "sdk.iam.enum":
        return {"ok": True, "roles": ["AppServerRole", "DbAdminRole"]}
    if technique_id == "sdk.ecr.enum":
        return {"ok": True, "repositories": ["web-api", "internal-tools"]}
    if technique_id == "sdk.ec2.sg_audit":
        return {
            "ok": True,
            "findings": [
                {
                    "resource": "sg-123456",
                    "issue": "Ingress from 0.0.0.0/0 on tcp port 22",
                    "severity": "high",
                    "evidence": {"from_port": 22, "to_port": 22},
                }
            ],
        }
    if technique_id == "sdk.kms.rotation_audit":
        return {
            "ok": True,
            "findings": [
                {"resource": "key-sandbox", "issue": "KMS key rotation disabled", "severity": "medium", "evidence": {}}
            ],
        }
    if technique_id == "sdk.iam.key_age":
        return {
            "ok": True,
            "findings": [
                {
                    "resource": "analyst:AKIA-OLDKEY",
                    "issue": "IAM access key age 148 days",
                    "severity": "medium",
                    "evidence": {"age_days": 148},
                }
            ],
        }
    if technique_id == "sdk.s3.public_policy_audit":
        return {
            "ok": True,
            "findings": [
                {
                    "resource": "public-audit-logs",
                    "issue": "Bucket policy allows public s3:GetObject",
                    "severity": "medium",
                    "evidence": {},
                }
            ],
        }
    return {"ok": False, "error": f"Unsupported SDK technique '{technique_id}' in simulation"}
