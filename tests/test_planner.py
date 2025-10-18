from app.planner import plan


def test_plan_includes_public_s3_bucket():
    facts = {
        "services": {
            "s3": [
                {"name": "public-bucket", "public": True},
            ]
        },
        "account": "123456789012",
        "region": "us-east-1",
    }

    runbook = plan(facts, goals=None)

    techniques = [step.technique_id for step in runbook.steps]
    assert "T-S3-001" in techniques
