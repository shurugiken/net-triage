"""Rendering of triage results into text or JSON."""

from __future__ import annotations

import json
from typing import Iterable

from .checks import CheckResult, FAIL, PASS, WARN, overall_verdict

# Plain-text status markers (ASCII-safe for any terminal / log file).
_MARKERS = {PASS: "[ OK ]", WARN: "[WARN]", FAIL: "[FAIL]"}


def render_text(host: str, results: list[CheckResult]) -> str:
    """Render a human-readable report."""
    lines = [f"net-triage report for: {host}", "=" * 60]
    for r in results:
        marker = _MARKERS.get(r.verdict, "[????]")
        lines.append(f"{marker} {r.name:<10} {r.summary}")
    lines.append("=" * 60)
    overall = overall_verdict(results)
    lines.append(f"OVERALL: {overall}")
    return "\n".join(lines)


def render_json(host: str, results: Iterable[CheckResult]) -> str:
    """Render results as a JSON document."""
    results = list(results)
    payload = {
        "host": host,
        "overall": overall_verdict(results),
        "checks": [r.to_dict() for r in results],
    }
    return json.dumps(payload, indent=2)
