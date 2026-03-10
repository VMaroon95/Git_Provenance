# 🔐 git-provenance


> **Part of the [meda-claw](https://github.com/VMaroon95/meda-claw) Governance Stack** — Install the full suite via `pip install meda-claw`**AI Governance & IP Compliance Firewall for Git**

> Enforcing algorithmic accountability in corporate software supply chains.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What It Does

`git-provenance` scans your Git history and enforces governance policies around AI-generated code:

- **🚨 AI Contribution Gating** — Block commits exceeding configurable AI-authorship thresholds (default: 50%)
- **✅ Model Allow-Listing** — Only approved AI tools (Copilot, Claude Code, Cursor Pro, etc.) are permitted
- **📊 Provenance Reports** — Structured JSON reports for legal, audit, and compliance teams
- **🔗 Git Hook Integration** — Pre-commit and pre-push enforcement in CI/CD pipelines
- **🏛️ IP Safety** — Protect intellectual property value by ensuring human contribution minimums

## Quick Start

```bash
# Scan the current repo (last 50 commits)
python core.py

# Scan with custom threshold
python core.py --threshold 30

# Output to file
python core.py -o provenance-report.json

# Use as pre-commit hook (exits 1 on policy violation)
python core.py --pre-commit --commits 1

# Scan a specific directory
python core.py --dir /path/to/repo -n 100
```

## Install as Git Hook

```python
from hooks import install_hook
install_hook("pre-commit")  # Blocks commits violating policy
```

## Provenance Report

Each scan generates a structured report:

```json
{
  "repo": "my-project",
  "total_commits_scanned": 50,
  "commits_with_ai": 3,
  "blocked_commits": 1,
  "warned_commits": 2,
  "overall_risk": "high",
  "policy_config": {
    "ai_percentage_threshold": 50,
    "model_allow_list": ["copilot", "claude-code", "cursor-pro"]
  },
  "commits": [...]
}
```

## Policy Rules

| Rule | Default | Action |
|------|---------|--------|
| AI contribution exceeds threshold | >50% | **BLOCK** |
| Unapproved AI model detected | Not in allow-list | **BLOCK** |
| Large commit, no attribution | >200 lines, no AI metadata | **WARN** |

## Configuration

Override defaults via CLI flags or modify `core.py` constants:

```python
AI_PERCENTAGE_THRESHOLD = 50    # Max AI-generated percentage
HUMAN_MIN_PERCENTAGE = 50       # Minimum human contribution
MODEL_ALLOW_LIST = [...]        # Approved AI tools
```

## Research Context

This tool supports academic research on:

> **"Enforcing Algorithmic Accountability in Corporate Software Supply Chains"**

Using `git-provenance` to create auditable links between AI-human agency and intellectual property value — bridging governance policy with empirical software engineering.

## Citing

If you use `git-provenance` in academic work, see [CITATION.cff](CITATION.cff).

---

**Built by [Varun Meda](https://github.com/VMaroon95)** — AI governance for the real world.
