from datetime import datetime, timedelta, timezone
import json

import boto3
import pytest
from botocore.stub import Stubber

from app.adapters import sdk


@pytest.fixture
def monkeypatched_boto3_client(monkeypatch):
    stubs = {}
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    def client(service_name, *args, **kwargs):
        real_client = boto3.client(service_name, *args, **kwargs)
        stub = Stubber(real_client)
        stubs[service_name] = stub
        return real_client

    monkeypatch.setattr(sdk.boto3, "client", client)
    yield stubs
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def _s3_policy(policy):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::bucket/*",
            }
        ],
    }


def test_ec2_security_group_audit(monkeypatched_boto3_client):
    stubs = monkeypatched_boto3_client
    ec2_client = sdk.boto3.client("ec2")
    stub = stubs["ec2"]
    stub.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-open",
                    "GroupName": "open-group",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                },
                {
                    "GroupId": "sg-safe",
                    "GroupName": "safe-group",
                    "IpPermissions": [],
                },
            ]
        },
    )
    stub.activate()

    result = sdk.run_sdk("sdk.ec2.sg_audit", "sdk", {})
    assert result["ok"] is True
    findings = result["findings"]
    assert any(f["security_group_id"] == "sg-open" for f in findings)


def test_kms_rotation_audit(monkeypatched_boto3_client):
    stubs = monkeypatched_boto3_client
    kms_client = sdk.boto3.client("kms")
    stub = stubs["kms"]
    stub.add_response("list_keys", {"Keys": [{"KeyId": "1234"}]})
    stub.add_response("get_key_rotation_status", {"KeyRotationEnabled": False}, {"KeyId": "1234"})
    stub.activate()

    result = sdk.run_sdk("sdk.kms.rotation_audit", "sdk", {})
    assert result["ok"] is True
    findings = result["findings"]
    assert findings == [{"key_id": "1234", "issue": "rotation_disabled"}]


def test_iam_key_age(monkeypatched_boto3_client):
    stubs = monkeypatched_boto3_client
    iam_client = sdk.boto3.client("iam")
    stub = stubs["iam"]
    stub.add_response("list_users", {"Users": [{"UserName": "old-user"}]})
    stub.add_response(
        "list_access_keys",
        {"AccessKeyMetadata": [{"AccessKeyId": "AKIAOLD", "CreateDate": datetime.now(timezone.utc) - timedelta(days=120)}]},
        {"UserName": "old-user"},
    )
    stub.activate()

    result = sdk.run_sdk("sdk.iam.key_age", "sdk", {})
    assert result["ok"] is True
    findings = result["findings"]
    assert findings and findings[0]["access_key_id"] == "AKIAOLD"


def test_s3_public_policy(monkeypatched_boto3_client):
    stubs = monkeypatched_boto3_client
    s3_client = sdk.boto3.client("s3")
    stub = stubs["s3"]
    stub.add_response("list_buckets", {"Buckets": [{"Name": "open-bucket"}]})
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": ["arn:aws:s3:::open-bucket/*"],
                }
            ],
        }
    )
    stub.add_response("get_bucket_policy", {"Policy": policy_doc}, {"Bucket": "open-bucket"})
    stub.activate()

    result = sdk.run_sdk("sdk.s3.public_policy_audit", "sdk", {})
    assert result["ok"] is True
    findings = result["findings"]
    assert any(f.get("bucket") == "open-bucket" and f.get("public") for f in findings)
