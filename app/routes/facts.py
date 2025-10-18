import json
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import require_auth

router = APIRouter()

ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"


def _principal_is_public(principal: Any) -> bool:
    if principal == "*" or principal == ["*"]:
        return True

    if isinstance(principal, dict):
        for value in principal.values():
            if value == "*" or (isinstance(value, list) and "*" in value):
                return True

    return False


def _bucket_acl_is_public(grants: List[Dict[str, Any]]) -> bool:
    for grant in grants:
        grantee = grant.get("Grantee", {})
        grant_uri = grantee.get("URI", "")
        if grantee.get("Type") == "Group" and grant_uri == ALL_USERS_URI:
            return True
    return False


def _bucket_policy_is_public(policy_doc: Dict[str, Any]) -> bool:
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if _principal_is_public(principal):
            return True
    return False


def _determine_bucket_public_status(s3_client, bucket_name: str) -> bool:
    try:
        acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
        if _bucket_acl_is_public(acl_response.get("Grants", [])):
            return True
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code not in {"NoSuchBucket", "AccessDenied"}:
            raise

    try:
        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_string = policy_response.get("Policy")
        if policy_string:
            policy_doc = json.loads(policy_string)
            if _bucket_policy_is_public(policy_doc):
                return True
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code not in {"NoSuchBucket", "AccessDenied", "NoSuchBucketPolicy", "MalformedPolicy"}:
            raise

    return False


def _list_bucket_summaries(s3_client) -> List[Dict[str, Any]]:
    try:
        buckets_response = s3_client.list_buckets()
    except ClientError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to list S3 buckets.",
        ) from exc

    summaries: List[Dict[str, Any]] = []
    for bucket in buckets_response.get("Buckets", []):
        name = bucket.get("Name")
        if not name:
            continue
        try:
            is_public = _determine_bucket_public_status(s3_client, name)
        except ClientError:
            is_public = False
        summaries.append({"name": name, "public": is_public})

    return summaries


async def gather_facts() -> Dict[str, Any]:
    try:
        sts_client = boto3.client("sts")
        s3_client = boto3.client("s3")
    except NoCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AWS credentials are not available.",
        ) from exc

    try:
        identity = sts_client.get_caller_identity()
        account_id = identity.get("Account")
    except ClientError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to fetch AWS account identity.",
        ) from exc

    s3_summaries = _list_bucket_summaries(s3_client)

    return {
        "account": account_id,
        "services": {"s3": s3_summaries},
    }


@router.get("/facts")
async def get_facts(_: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    return await gather_facts()
