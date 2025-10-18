#!/usr/bin/env python3
"""Smoke-test the CloudArena SDK audits against a real AWS environment."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, List

import boto3

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.adapters import sdk as sdk_adapter

AUDIT_TECHNIQUES = [
    "sdk.ec2.sg_audit",
    "sdk.kms.rotation_audit",
    "sdk.iam.key_age",
    "sdk.s3.public_policy_audit",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--techniques",
        nargs="*",
        default=AUDIT_TECHNIQUES,
        help="Specific audit technique ids to run (default: all supported)",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS region to target (defaults to active profile configuration)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of human-readable text",
    )
    return parser.parse_args()


def verify_credentials(region: str | None) -> dict:
    sts = boto3.client("sts", region_name=region)
    identity = sts.get_caller_identity()
    return identity


def run_audits(techniques: Iterable[str]) -> List[dict]:
    results: List[dict] = []
    for technique_id in techniques:
        result = sdk_adapter.run_sdk(technique_id, "sdk", params={})
        results.append({"technique": technique_id, **result})
    return results


def main() -> None:
    args = parse_args()

    if args.region:
        boto3.setup_default_session(region_name=args.region)

    identity = verify_credentials(args.region)
    results = run_audits(args.techniques)

    if args.json:
        output = {
            "identity": identity,
            "results": results,
        }
        json.dump(output, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return

    print("AWS Identity:")
    print(f"  Account: {identity['Account']}")
    print(f"  ARN:     {identity['Arn']}")
    print("  UserId:  {UserId}".format(**identity))
    print("\nAudit Results:")

    for record in results:
        technique = record.get("technique")
        ok = record.get("ok")
        error = record.get("error")
        findings = record.get("findings") or []
        print(f"- {technique}: {'ok' if ok else 'error'}")
        if not ok:
            print(f"    error: {error}")
            continue
        if not findings:
            print("    findings: none")
            continue
        print(f"    findings ({len(findings)}):")
        for finding in findings[:5]:
            resource = finding.get("resource", "n/a")
            issue = finding.get("issue", "n/a")
            severity = finding.get("severity", "n/a")
            print(f"      - [{severity}] {resource}: {issue}")
        if len(findings) > 5:
            print(f"      ... {len(findings) - 5} more")


if __name__ == "__main__":
    main()
