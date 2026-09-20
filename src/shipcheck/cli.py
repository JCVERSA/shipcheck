"""Command-line entrypoint for shipcheck."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .checks import run_all_checks
from .report import render_json, render_markdown


def _print_table(findings):
    if not findings:
        print("No findings. Looks ship-shape. :ship:")
        return
    widths = [8, 10, 30, 40, 40]
    headers = ["SEVERITY", "CATEGORY", "LOCATION", "PROBLEM", "FIX"]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("  ".join("-" * w for w in widths))
    for f in findings:
        row = [f.severity, f.category, f.location, f.problem[:38], f.fix[:38]]
        print("  ".join(c.ljust(w) for c, w in zip(row, widths)))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="shipcheck",
        description="Audit a repository for production-readiness.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repo root to audit (default: current directory)")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable JSON report")
    parser.add_argument("--markdown", action="store_true", help="Emit a Markdown report")
    parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default="HIGH",
                        help="Exit non-zero when findings at or above this severity exist (default: HIGH)")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    findings = run_all_checks(root)

    if args.json:
        print(render_json(findings, root))
    elif args.markdown:
        print(render_markdown(findings, root))
    else:
        _print_table(findings)

    threshold = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[args.fail_on]
    blocking = [f for f in findings if {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.severity, 99) <= threshold]
    if blocking:
        print(f"\nFAIL: {len(blocking)} finding(s) at or above {args.fail_on}", file=sys.stderr)
        return 1
    print(f"\nPASS: no findings at or above {args.fail_on}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
