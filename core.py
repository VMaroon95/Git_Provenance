"""
git-provenance — AI Governance & IP Compliance Firewall for Git

Enforces provenance tracking, AI contribution gating, and audit-ready
reporting across software supply chains.

Author: Varun Meda (github.com/VMaroon95)
License: MIT
"""

import json
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


# ── Configuration ────────────────────────────────────────────────────

AI_PERCENTAGE_THRESHOLD = 50  # Max allowed AI-generated content (%)
HUMAN_MIN_PERCENTAGE = 50     # Minimum human contribution required

MODEL_ALLOW_LIST = [
    "copilot",
    "claude-code",
    "cursor-pro",
    "codewhisperer",
    "codex",
    "gemini-code-assist",
]

# Patterns that signal AI-generated code in commit messages / metadata
AI_INDICATORS = [
    r"(?i)co-?authored-?by:.*\b(copilot|claude|cursor|codewhisperer|codex|gemini)\b",
    r"(?i)generated\s+(by|with|via)\s+(ai|llm|copilot|claude|cursor)",
    r"(?i)ai[- ]assisted",
    r"(?i)\b(copilot|claude|cursor|codewhisperer)\b.*suggestion",
]

# ── Enums ────────────────────────────────────────────────────────────

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyVerdict(Enum):
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


# ── Data Models ──────────────────────────────────────────────────────

@dataclass
class AIContribution:
    model: str
    confidence: float          # 0.0 – 1.0
    lines_attributed: int
    indicator_matched: str


@dataclass
class CommitProvenance:
    sha: str
    author: str
    date: str
    message: str
    files_changed: int
    lines_added: int
    lines_removed: int
    ai_contributions: list[AIContribution] = field(default_factory=list)
    ai_percentage: float = 0.0
    human_percentage: float = 100.0
    risk_level: RiskLevel = RiskLevel.LOW
    verdict: PolicyVerdict = PolicyVerdict.PASS
    violations: list[str] = field(default_factory=list)


@dataclass
class ProvenanceReport:
    repo: str
    generated_at: str
    total_commits_scanned: int
    commits_with_ai: int
    blocked_commits: int
    warned_commits: int
    overall_risk: RiskLevel
    policy_config: dict
    commits: list[CommitProvenance] = field(default_factory=list)


# ── Git Interface ────────────────────────────────────────────────────

def _run(cmd: list[str], cwd: Optional[str] = None) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")
    return result.stdout.strip()


def get_repo_name(cwd: Optional[str] = None) -> str:
    url = _run(["git", "remote", "get-url", "origin"], cwd=cwd)
    name = url.rstrip("/").split("/")[-1]
    return name.removesuffix(".git")


def get_commits(n: int = 50, cwd: Optional[str] = None) -> list[dict]:
    """Retrieve last n commits with metadata."""
    fmt = "%H|||%an|||%aI|||%s"
    log = _run(
        ["git", "log", f"-{n}", f"--pretty=format:{fmt}", "--shortstat"],
        cwd=cwd,
    )
    commits = []
    lines = log.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if "|||" in line:
            parts = line.split("|||")
            sha, author, date, message = parts[0], parts[1], parts[2], parts[3]
            # Next non-empty line is the shortstat
            added = removed = changed = 0
            i += 1
            while i < len(lines) and not lines[i].strip():
                i += 1
            if i < len(lines) and "file" in lines[i]:
                stat = lines[i].strip()
                m_changed = re.search(r"(\d+) file", stat)
                m_added = re.search(r"(\d+) insertion", stat)
                m_removed = re.search(r"(\d+) deletion", stat)
                changed = int(m_changed.group(1)) if m_changed else 0
                added = int(m_added.group(1)) if m_added else 0
                removed = int(m_removed.group(1)) if m_removed else 0
            commits.append({
                "sha": sha, "author": author, "date": date,
                "message": message, "files_changed": changed,
                "lines_added": added, "lines_removed": removed,
            })
        i += 1
    return commits


# ── AI Detection Engine ──────────────────────────────────────────────

def detect_ai_contribution(commit: dict) -> list[AIContribution]:
    """Scan commit message and metadata for AI generation signals."""
    contributions = []
    msg = commit["message"]

    for pattern in AI_INDICATORS:
        match = re.search(pattern, msg)
        if match:
            # Extract model name
            model = "unknown"
            for m in MODEL_ALLOW_LIST:
                if m.lower() in match.group(0).lower():
                    model = m
                    break

            lines = commit["lines_added"]
            contributions.append(AIContribution(
                model=model,
                confidence=0.85 if model != "unknown" else 0.5,
                lines_attributed=lines,
                indicator_matched=pattern,
            ))
    return contributions


def calculate_ai_percentage(commit: dict, contributions: list[AIContribution]) -> float:
    """Estimate AI-generated percentage of a commit."""
    if not contributions:
        return 0.0
    total_lines = commit["lines_added"] + commit["lines_removed"]
    if total_lines == 0:
        return 0.0
    ai_lines = sum(c.lines_attributed for c in contributions)
    return min(100.0, round((ai_lines / total_lines) * 100, 1))


# ── Policy Engine ────────────────────────────────────────────────────

def evaluate_policy(provenance: CommitProvenance) -> CommitProvenance:
    """Apply governance rules to a commit's provenance data."""

    # Rule 1: AI percentage exceeds threshold
    if provenance.ai_percentage > AI_PERCENTAGE_THRESHOLD:
        provenance.violations.append(
            f"AI contribution ({provenance.ai_percentage}%) exceeds "
            f"threshold ({AI_PERCENTAGE_THRESHOLD}%)"
        )
        provenance.verdict = PolicyVerdict.BLOCK
        provenance.risk_level = RiskLevel.CRITICAL

    # Rule 2: Disallowed AI model
    for contrib in provenance.ai_contributions:
        if contrib.model not in MODEL_ALLOW_LIST and contrib.model != "unknown":
            provenance.violations.append(
                f"Unapproved AI model detected: {contrib.model}"
            )
            provenance.verdict = PolicyVerdict.BLOCK
            provenance.risk_level = RiskLevel.HIGH

    # Rule 3: No provenance metadata (high lines, no attribution)
    if provenance.lines_added > 200 and not provenance.ai_contributions:
        provenance.violations.append(
            "Large commit with no provenance attribution — manual review recommended"
        )
        if provenance.verdict == PolicyVerdict.PASS:
            provenance.verdict = PolicyVerdict.WARN
            provenance.risk_level = RiskLevel.MEDIUM

    # Set risk for detected-but-compliant AI usage
    if provenance.ai_contributions and provenance.verdict == PolicyVerdict.PASS:
        provenance.risk_level = RiskLevel.LOW

    provenance.human_percentage = round(100 - provenance.ai_percentage, 1)
    return provenance


# ── Report Generator ─────────────────────────────────────────────────

def generate_report(
    n_commits: int = 50,
    cwd: Optional[str] = None,
    output: Optional[str] = None,
) -> ProvenanceReport:
    """Scan a repo and produce a structured provenance report."""

    repo = get_repo_name(cwd)
    commits_raw = get_commits(n=n_commits, cwd=cwd)

    report = ProvenanceReport(
        repo=repo,
        generated_at=datetime.now(timezone.utc).isoformat(),
        total_commits_scanned=len(commits_raw),
        commits_with_ai=0,
        blocked_commits=0,
        warned_commits=0,
        overall_risk=RiskLevel.LOW,
        policy_config={
            "ai_percentage_threshold": AI_PERCENTAGE_THRESHOLD,
            "human_min_percentage": HUMAN_MIN_PERCENTAGE,
            "model_allow_list": MODEL_ALLOW_LIST,
        },
    )

    for raw in commits_raw:
        ai = detect_ai_contribution(raw)
        pct = calculate_ai_percentage(raw, ai)

        prov = CommitProvenance(
            sha=raw["sha"],
            author=raw["author"],
            date=raw["date"],
            message=raw["message"],
            files_changed=raw["files_changed"],
            lines_added=raw["lines_added"],
            lines_removed=raw["lines_removed"],
            ai_contributions=ai,
            ai_percentage=pct,
        )

        prov = evaluate_policy(prov)
        report.commits.append(prov)

        if ai:
            report.commits_with_ai += 1
        if prov.verdict == PolicyVerdict.BLOCK:
            report.blocked_commits += 1
        if prov.verdict == PolicyVerdict.WARN:
            report.warned_commits += 1

    # Overall risk = worst across all commits
    risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    worst = max(report.commits, key=lambda c: risk_order.index(c.risk_level), default=None)
    if worst:
        report.overall_risk = worst.risk_level

    # Output
    if output:
        Path(output).write_text(json.dumps(_serialize(report), indent=2))
        print(f"📄 Report written to {output}")
    else:
        print(json.dumps(_serialize(report), indent=2))

    return report


def _serialize(obj):
    """Convert dataclasses + enums to JSON-safe dicts."""
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _serialize(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_serialize(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    return obj


# ── CLI Entry ────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="git-provenance",
        description="AI Governance & IP Compliance Firewall for Git",
    )
    parser.add_argument("-n", "--commits", type=int, default=50, help="Number of commits to scan")
    parser.add_argument("-d", "--dir", type=str, default=None, help="Git repo directory")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output JSON file path")
    parser.add_argument("--threshold", type=int, default=None, help="Override AI percentage threshold")
    parser.add_argument("--pre-commit", action="store_true", help="Run as pre-commit hook (exit 1 on BLOCK)")

    args = parser.parse_args()

    if args.threshold is not None:
        global AI_PERCENTAGE_THRESHOLD
        AI_PERCENTAGE_THRESHOLD = args.threshold

    report = generate_report(n_commits=args.commits, cwd=args.dir, output=args.output)

    # Summary
    print(f"\n{'='*60}")
    print(f"  git-provenance — {report.repo}")
    print(f"{'='*60}")
    print(f"  Commits scanned:  {report.total_commits_scanned}")
    print(f"  AI-assisted:      {report.commits_with_ai}")
    print(f"  Blocked:          {report.blocked_commits}")
    print(f"  Warnings:         {report.warned_commits}")
    print(f"  Overall risk:     {report.overall_risk.value.upper()}")
    print(f"{'='*60}\n")

    if args.pre_commit and report.blocked_commits > 0:
        print("❌ BLOCKED — commit violates AI governance policy.")
        sys.exit(1)

    if report.blocked_commits > 0:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
