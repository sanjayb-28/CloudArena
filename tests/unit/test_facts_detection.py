from types import SimpleNamespace

import boto3
import pytest

from app.routes.facts import gather_facts


@pytest.fixture
def mock_boto3_client(monkeypatch):
    original_client = boto3.client
    original_session = boto3.session.Session

    def client(service_name, *args, **kwargs):
        if service_name == "sts":
            return SimpleNamespace(get_caller_identity=lambda: {"Account": "123456789012"})
        if service_name == "s3":
            return SimpleNamespace(
                list_buckets=lambda: {"Buckets": []},
                get_bucket_acl=lambda **kwargs: {"Grants": []},
                get_bucket_policy=lambda **kwargs: {"Policy": ""},
            )
        if service_name == "iam":
            return SimpleNamespace(list_users=lambda **kwargs: {"Users": []})
        if service_name == "ec2":
            return SimpleNamespace(describe_instances=lambda **kwargs: {"Reservations": []})
        if service_name == "kms":
            return SimpleNamespace(list_keys=lambda **kwargs: {"Keys": []})
        if service_name == "ecr":
            return SimpleNamespace(describe_repositories=lambda **kwargs: {"repositories": []})
        return original_client(service_name, *args, **kwargs)

    monkeypatch.setattr(boto3, "client", client)
    monkeypatch.setattr(boto3.session, "Session", lambda: SimpleNamespace(region_name="us-east-1"))


@pytest.mark.asyncio
async def test_gather_facts_sets_service_flags(mock_boto3_client):
    facts = await gather_facts()

    services = facts["services"]
    assert services["iam"] is True
    assert services["ec2"] is True
    assert services["kms"] is True
    assert services["ecr"] is True
