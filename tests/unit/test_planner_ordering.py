import pytest

from app.planner import plan


def test_planner_orders_techniques(facts_builder):
    facts = facts_builder(
        public_buckets=[("bucket-1", True)],
        services={
            "iam": True,
            "ec2": True,
            "kms": True,
            "ecr": True,
        },
    )

    runbook = plan(facts, goals=None)
    order = [step.technique_id for step in runbook.steps]

    assert order == [
        "T-S3-001",
        "T-S3-PUBLIC-POLICY",
        "T-EC2-SG-OPEN",
        "T-IAM-KEY-AGE",
        "T-KMS-ROTATION",
        "T-IAM-ENUM",
        "T-ECR-ENUM",
    ]


def test_planner_skips_optional_services(facts_builder):
    facts = facts_builder(
        public_buckets=[("bucket-1", True)],
        services={"iam": False, "ec2": False, "kms": False, "ecr": False},
    )

    runbook = plan(facts, goals=None)
    order = [step.technique_id for step in runbook.steps]

    assert order == [
        "T-S3-001",
        "T-S3-PUBLIC-POLICY",
    ]
