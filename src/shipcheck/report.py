"""Render audit findings as Markdown or JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

from .checks import SEVERITY_ORDER, Finding


def render_markdown(findings: Iterable[Finding], root: str = ".") -> str:
    lines = [f"# shipcheck report - {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}", ""]
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    verdict = "PASS" if not any(
        f.severity in ("CRITICAL", "HIGH") for f in findings
    ) else "FAIL"
    lines.append(f"**Verdict: {verdict}**")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")
    lines.append("")

    if not findings:
        lines.append("No findings. Looks ship-shape. :ship:")
        return "\n".join(lines)

    lines.append("| Severity | Category | Location | Problem | Fix |")
    lines.append("|---|---|---|---|---|")
    for f in findings:
        lines.append(
            f"| {f.severity} | {f.category} | `{f.location}` | {f.problem} | {f.fix} |"
        )
    return "\n".join(lines)


def render_json(findings: Iterable[Finding], root: str = ".") -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": root,
        "finding_count": len(list(findings)) if not isinstance(findings, list) else len(findings),
        "findings": [f.as_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)
