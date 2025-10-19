"""Ingestion utilities for normalizing worker output before persistence."""

from .normalizer import SEVERITY_ORDER, coerce_finding, max_severity, normalize_result, summarize_findings
from .summaries import available_summaries, register_summary

__all__ = [
    "SEVERITY_ORDER",
    "coerce_finding",
    "max_severity",
    "normalize_result",
    "summarize_findings",
    "register_summary",
    "available_summaries",
]
