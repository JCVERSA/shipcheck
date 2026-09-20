# shipcheck

Audit any repository for **production-readiness** from the command line.
Pure Python, zero runtime dependencies, CI-friendly exit codes.

## What it checks

| Category | Checks |
|---|---|
| Security | Hardcoded AWS keys, GitHub/Slack tokens, private key blocks, generic `password=`/`api_key=` assignments |
| Hygiene | Committed `.env`, missing `.gitignore` |
| Code smells | Bare `except:`, TODO/FIXME/HACK markers |
| Metadata | Missing README, LICENSE, or CI workflow |

## Install

```bash
pip install -e .
```

## Usage

```bash
# audit current directory (table output)
shipcheck .

# Markdown report
shipcheck . --markdown

# JSON report for CI tooling
shipcheck . --json

# fail the build on MEDIUM or worse
shipcheck . --fail-on MEDIUM
```

Exit codes: `0` pass, `1` findings at/above `--fail-on`, `2` usage error.

## Development

```bash
pip install -e . pytest
pytest -v
```

## Status

MIT licensed. See [LICENSE](LICENSE).
