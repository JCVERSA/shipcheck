"""shipcheck - production-readiness auditor for code repositories."""

from .checks import run_all_checks
from .report import render_markdown, render_json

__version__ = "0.1.0"

__all__ = ["run_all_checks", "render_markdown", "render_json", "__version__"]
