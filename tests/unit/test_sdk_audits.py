from datetime import datetime, timedelta, timezone
import json

import pytest

from app.adapters import sdk


def test_ec2_security_group_audit(monkeypatch):
    class FakePaginator:
        def paginate(self):
            yield {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-open",
                        "GroupName": "open-group",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "open ssh"}],
                            }
                        ],
                    }
                ]
            }

    class FakeEC2:
        def get_paginator(self, name):
            assert name == "describe_security_groups"
            return FakePaginator()

    monkeypatch.setattr(sdk.boto3, "client", lambda name, **kwargs: FakeEC2(), raising=False)

    result = sdk.run_sdk("sdk.ec2.sg_audit", "sdk", {})
    findings = result["findings"]
    assert findings and findings[0]["resource"] == "sg-open"
    assert findings[0]["severity"] == "high"


def test_kms_rotation_audit(monkeypatch):
    class FakePaginator:
        def paginate(self):
            yield {"Keys": [{"KeyId": "1234"}]}

    class FakeKMS:
        def get_paginator(self, name):
            assert name == "list_keys"
            return FakePaginator()

        def get_key_rotation_status(self, KeyId):
            assert KeyId == "1234"
            return {"KeyRotationEnabled": False}

    monkeypatch.setattr(sdk.boto3, "client", lambda name, **kwargs: FakeKMS(), raising=False)

    result = sdk.run_sdk("sdk.kms.rotation_audit", "sdk", {})
    assert result["findings"] == [
        {
            "resource": "1234",
            "issue": "KMS key rotation disabled",
            "severity": "medium",
            "evidence": {"rotation_enabled": False},
        }
    ]


def test_iam_key_age(monkeypatch):
    now = datetime.now(timezone.utc)

    class FakePaginator:
        def paginate(self):
            yield {"Users": [{"UserName": "old-user"}]}

    class FakeIAM:
        def get_paginator(self, name):
            assert name == "list_users"
            return FakePaginator()

        def list_access_keys(self, UserName):
            assert UserName == "old-user"
            return {
                "AccessKeyMetadata": [
                    {
                        "AccessKeyId": "AKIAOLD",
                        "CreateDate": now - timedelta(days=120),
                    }
                ]
            }

    monkeypatch.setattr(sdk.boto3, "client", lambda name, **kwargs: FakeIAM(), raising=False)

    result = sdk.run_sdk("sdk.iam.key_age", "sdk", {})
    findings = result["findings"]
    assert findings and findings[0]["resource"].endswith("AKIAOLD")


def test_s3_public_policy(monkeypatch):
    policy = {
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

    class FakeS3:
        def list_buckets(self):
            return {"Buckets": [{"Name": "open-bucket"}]}

        def get_bucket_policy(self, Bucket):
            assert Bucket == "open-bucket"
            return {"Policy": json.dumps(policy)}

    monkeypatch.setattr(sdk.boto3, "client", lambda name, **kwargs: FakeS3(), raising=False)

    result = sdk.run_sdk("sdk.s3.public_policy_audit", "sdk", {})
    findings = result["findings"]
    assert findings and findings[0]["resource"] == "open-bucket"
