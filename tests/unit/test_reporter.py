from datetime import datetime, timezone

from app.reporter import render_report


def _build_event(
    technique_id: str,
    severity: str,
    summary: str,
    findings: list[dict],
    resource: str | None = None,
):
    return {
        "run_id": "run-1",
        "event_type": "run.step",
        "payload": {
            "event_type": "run.step",
            "index": 1,
            "technique_id": technique_id,
            "status": "ok",
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "resource": resource,
        "summary": summary,
        "details": {"findings": findings},
    }


def test_reporter_generates_markdown_with_findings(facts_builder):
    facts = facts_builder(
        public_buckets=[("public-bucket", True)],
        services={"iam": True, "ec2": True, "kms": True, "ecr": True},
    )

    events = [
        _build_event(
            "T-EC2-SG-OPEN",
            "high",
            "1 security group allows 0.0.0.0/0 (ports: 22)",
            [
                {
                    "resource": "sg-123",
                    "issue": "Ingress from 0.0.0.0/0 on tcp port 22",
                    "severity": "high",
                    "evidence": {"from_port": 22, "to_port": 22},
                }
            ],
        ),
        _build_event(
            "T-KMS-ROTATION",
            "medium",
            "1 KMS key with rotation disabled",
            [
                {
                    "resource": "key-1",
                    "issue": "KMS key rotation disabled",
                    "severity": "medium",
                    "evidence": {"rotation_enabled": False},
                }
            ],
        ),
        {
            "run_id": "run-1",
            "event_type": "run.completed",
            "payload": {"event_type": "run.completed", "status": "ok", "step_count": 2},
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    ]

    markdown = render_report(facts, events)

    assert "High: **1** | Medium: **1**" in markdown
    assert "Top Risks" in markdown
    assert "T-EC2-SG-OPEN" in markdown
    assert "sg-123" in markdown
    assert "Restrict security group source CIDRs" in markdown
    assert "Enable automatic rotation on KMS keys" in markdown
    assert "public-bucket" in markdown
