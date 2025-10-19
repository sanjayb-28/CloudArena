"""Utilities for aggregating run events into step summaries."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Optional, Tuple

StepKey = Tuple[Optional[int], Optional[str]]


def aggregate_step_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse per-step events into a single summary record.

    The order is preserved based on first occurrence of a step index.
    """

    records: "OrderedDict[StepKey, Dict[str, Any]]" = OrderedDict()

    for event in events:
        payload = event.get("payload") or {}
        if payload.get("event_type") != "run.step":
            continue

        index = payload.get("index")
        technique_id = payload.get("technique_id")
        key: StepKey = (index, technique_id)
        record = records.get(key)
        if record is None:
            record = {
                "index": index,
                "technique_id": technique_id,
                "status": None,
                "phase": None,
                "severity": None,
                "summary": None,
                "details": {},
                "resource": None,
                "artifacts": [],
            }
            records[key] = record

        status = event.get("status") or payload.get("status")
        if status:
            record["status"] = status

        phase = event.get("phase") or record.get("phase")
        if phase:
            record["phase"] = phase

        severity = event.get("severity") or payload.get("severity")
        if severity:
            record["severity"] = severity

        resource = event.get("resource") or payload.get("resource")
        if resource:
            record["resource"] = resource

        summary = event.get("summary") or payload.get("summary")
        if summary:
            record["summary"] = summary

        details = event.get("details") or payload.get("details")
        if isinstance(details, dict):
            record["details"] = details

        artifacts = event.get("artifacts") or payload.get("artifacts")
        if artifacts:
            record.setdefault("artifacts", []).extend(artifacts)

    return list(records.values())
