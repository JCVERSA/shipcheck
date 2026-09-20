"""Check engine: security, hygiene, code-smell and metadata checks."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Finding:
    """A single audit finding."""

    severity: str
    category: str
    location: str
    problem: str
    fix: str

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "location": self.location,
            "problem": self.problem,
            "fix": self.fix,
        }


SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic assignment secret", re.compile(
        r"(?i)(api_key|apikey|secret|password|passwd|token)\s*[=:]\s*['\"][^'\"]{8,}['\"]")),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache", ".pytest_cache"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".whl", ".woff", ".woff2"}


def _iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if os.path.splitext(name)[1].lower() in BINARY_EXT:
                continue
            yield path


def _read_text(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


def check_secrets(root: str):
    findings = []
    for path in _iter_files(root):
        text = _read_text(path)
        if not text:
            continue
        for label, pattern in SECRET_PATTERNS:
            m = pattern.search(text)
            if m:
                findings.append(Finding(
                    severity="CRITICAL",
                    category="security",
                    location=path,
                    problem=f"Possible hardcoded secret ({label}): {m.group(0)[:12]}...",
                    fix="Move the secret to an environment variable or secret manager and rotate it.",
                ))
                break  # one finding per file is enough
    return findings


def check_hygiene(root: str):
    findings = []
    env_path = os.path.join(root, ".env")
    if os.path.isfile(env_path):
        findings.append(Finding(
            severity="HIGH",
            category="hygiene",
            location=".env",
            problem="A .env file is tracked in the repository.",
            fix="Add .env to .gitignore, remove it from the repo and rotate exposed values.",
        ))
    gitignore = os.path.join(root, ".gitignore")
    if not os.path.isfile(gitignore):
        findings.append(Finding(
            severity="MEDIUM",
            category="hygiene",
            location=".gitignore",
            problem="Repository has no .gitignore file.",
            fix="Add a .gitignore covering OS, editor and build artifacts.",
        ))
    return findings


def check_smells(root: str):
    findings = []
    for path in _iter_files(root):
        if not path.endswith(".py"):
            continue
        text = _read_text(path)
        if not text:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if re.match(r"except\s*:", stripped):
                findings.append(Finding(
                    severity="MEDIUM",
                    category="code-smell",
                    location=f"{path}:{i}",
                    problem="Bare 'except:' swallows every exception, including SystemExit.",
                    fix="Catch specific exceptions or re-raise.",
                ))
            elif re.search(r"\b(TODO|FIXME|HACK)\b", stripped):
                findings.append(Finding(
                    severity="LOW",
                    category="code-smell",
                    location=f"{path}:{i}",
                    problem=f"Unresolved marker: {stripped[:60]}",
                    fix="Resolve the item or track it in an issue.",
                ))
    return findings


def check_metadata(root: str):
    findings = []
    checks = [
        ("README.md", "MEDIUM", "Repository has no README."),
        ("LICENSE", "LOW", "Repository has no LICENSE file."),
        (".github/workflows", "MEDIUM", "No CI workflow configured."),
    ]
    for rel, sev, msg in checks:
        if not os.path.exists(os.path.join(root, rel)):
            findings.append(Finding(
                severity=sev,
                category="metadata",
                location=rel,
                problem=msg,
                fix=f"Add {rel} so the project is production-ready.",
            ))
    return findings


ALL_CHECKS = {
    "secrets": check_secrets,
    "hygiene": check_hygiene,
    "smells": check_smells,
    "metadata": check_metadata,
}


def run_all_checks(root: str = "."):
    """Run every check and return findings sorted by severity."""
    findings = []
    for check in ALL_CHECKS.values():
        findings.extend(check(root))
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings
