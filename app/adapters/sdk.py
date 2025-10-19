"""Adapters for invoking CloudArena SDK techniques via AWS SDKs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.ingest import SEVERITY_ORDER

HandlerFunc = Callable[[str, Dict[str, Any]], Dict[str, Any]]


_HANDLERS: Dict[str, HandlerFunc] = {}


def register_handler(identifier: str) -> Callable[[HandlerFunc], HandlerFunc]:
    """Decorator to register an SDK handler for a catalog technique."""

    def decorator(func: HandlerFunc) -> HandlerFunc:
        if identifier in _HANDLERS:
            raise ValueError(f"Handler already registered for '{identifier}'")
        _HANDLERS[identifier] = func
        return func

    return decorator


def available_handlers() -> List[str]:
    """Return the list of registered handler identifiers."""

    return sorted(_HANDLERS.keys())


def _overall_severity(findings: List[Dict[str, Any]], default: str = "informational") -> str:
    highest = default
    for finding in findings:
        severity = str(finding.get("severity") or highest).lower()
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest, 0):
            highest = severity
    return highest


def _result_ok(
    summary: str,
    *,
    findings: Optional[List[Dict[str, Any]]] = None,
    severity: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    extras: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {"ok": True, "summary": summary}
    if findings is not None:
        result["findings"] = findings
        severity = severity or _overall_severity(findings)
    if severity:
        result["severity"] = severity
    if details is not None:
        result["details"] = details
    if extras:
        result.update(extras)
    return result


def _result_error(message: str, *, severity: str = "high", details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ok": False,
        "error": message,
        "summary": message,
    }
    if severity:
        result["severity"] = severity
    if details is not None:
        result["details"] = details
    return result


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
                severity = "informational"
                if age_days > 180:
                    severity = "high"
                elif age_days > 90:
                    severity = "medium"

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


def run_sdk(identifier: str, adapter: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a technique implemented via AWS SDK primitives."""

    if adapter != "sdk":
        raise ValueError(f"Unsupported adapter '{adapter}' for SDK runner")

    handler = _HANDLERS.get(identifier)
    if not handler:
        raise ValueError(f"Unsupported SDK technique '{identifier}'")

    try:
        return handler(identifier, params or {})
    except (BotoCoreError, ClientError) as exc:
        return _result_error(str(exc), severity="high")


@register_handler("sdk.iam.enum")
def _handle_iam_enum(identifier: str, params: Dict[str, Any]) -> Dict[str, Any]:  # noqa: ARG001
    roles = _list_iam_roles()
    summary = f"Enumerated {len(roles)} IAM roles"
    details = {"role_count": len(roles), "roles": roles[:50]}
    return _result_ok(summary, severity="informational", details=details, extras={"roles": roles})


@register_handler("sdk.ecr.enum")
def _handle_ecr_enum(identifier: str, params: Dict[str, Any]) -> Dict[str, Any]:  # noqa: ARG001
    repos = _list_ecr_repositories()
    summary = f"Enumerated {len(repos)} ECR repositories"
    details = {"repository_count": len(repos), "repositories": repos[:50]}
    return _result_ok(summary, severity="informational", details=details, extras={"repositories": repos})


@register_handler("sdk.ec2.sg_audit")
def _handle_ec2_sg_audit(identifier: str, params: Dict[str, Any]) -> Dict[str, Any]:  # noqa: ARG001
    findings = _audit_security_groups()
    summary = (
        "No internet-exposed security groups detected"
        if not findings
        else f"Identified {len(findings)} security groups with 0.0.0.0/0 ingress"
    )
    details = {"finding_count": len(findings)}
    severity = "informational" if not findings else "medium"
    return _result_ok(summary, findings=findings, details=details, severity=severity)


@register_handler("sdk.kms.rotation_audit")
def _handle_kms_rotation(identifier: str, params: Dict[str, Any]) -> Dict[str, Any]:  # noqa: ARG001
    findings = _audit_kms_rotation()
    summary = (
        "All KMS keys have rotation enabled"
        if not findings
        else f"{len(findings)} KMS keys require rotation attention"
    )
    details = {"finding_count": len(findings)}
    severity = "informational" if not findings else "medium"
    return _result_ok(summary, findings=findings, details=details, severity=severity)


@register_handler("sdk.iam.key_age")
def _handle_iam_key_age(identifier: str, params: Dict[str, Any]) -> Dict[str, Any]:  # noqa: ARG001
    max_age_days = params.get("max_age_days")
    try:
        threshold = int(max_age_days) if max_age_days is not None else 90
    except (TypeError, ValueError):
        threshold = 90

    candidate_findings = _audit_iam_key_age()
    findings: List[Dict[str, Any]] = []

    for finding in candidate_findings:
        evidence = finding.get("evidence", {})
        age = evidence.get("age_days")
        if not isinstance(age, (int, float)):
            continue
        if age >= threshold:
            if age >= 180:
                finding["severity"] = "high"
            elif age >= max(threshold, 90):
                finding["severity"] = "medium"
            else:
                # Sandbox thresholds may lower the bar; mark as medium to highlight risk.
                finding["severity"] = "medium"
                finding["issue"] = f"IAM access key age {age} days (threshold {threshold})"
            findings.append(finding)

    findings.sort(key=lambda item: item.get("evidence", {}).get("age_days", 0), reverse=True)
    summary = (
        "No stale IAM access keys detected"
        if not findings
        else f"{len(findings)} IAM access keys exceed age policy (>= {threshold} days)"
    )
    details = {"finding_count": len(findings)}
    severity = "informational" if not findings else max(
        (finding.get("severity", "medium") for finding in findings),
        key=lambda level: SEVERITY_ORDER.get(str(level).lower(), 0),
    )
    return _result_ok(summary, findings=findings, details=details, severity=severity)


@register_handler("sdk.s3.public_policy_audit")
def _handle_s3_public_policy(identifier: str, params: Dict[str, Any]) -> Dict[str, Any]:  # noqa: ARG001
    findings = _audit_s3_public_policies()
    summary = (
        "No publicly accessible S3 bucket policies detected"
        if not findings
        else f"{len(findings)} S3 buckets expose public access via policy"
    )
    details = {"finding_count": len(findings)}
    severity = "informational" if not findings else "medium"
    return _result_ok(summary, findings=findings, details=details, severity=severity)
