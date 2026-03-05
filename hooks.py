"""
git-provenance hooks — Git hook integration for CI/CD pipelines.

Install as pre-commit or pre-push hook for real-time governance enforcement.
"""

import subprocess
import sys
from pathlib import Path


HOOK_SCRIPT = """#!/bin/sh
# git-provenance pre-commit hook
python3 -m git_provenance --pre-commit --commits 1
"""


def install_hook(hook_type: str = "pre-commit", repo_dir: str = "."):
    """Install git-provenance as a git hook."""
    hooks_dir = Path(repo_dir) / ".git" / "hooks"
    if not hooks_dir.exists():
        print(f"❌ Not a git repository: {repo_dir}")
        sys.exit(1)

    hook_path = hooks_dir / hook_type
    hook_path.write_text(HOOK_SCRIPT)
    hook_path.chmod(0o755)
    print(f"✅ Installed {hook_type} hook at {hook_path}")


def uninstall_hook(hook_type: str = "pre-commit", repo_dir: str = "."):
    """Remove git-provenance hook."""
    hook_path = Path(repo_dir) / ".git" / "hooks" / hook_type
    if hook_path.exists():
        hook_path.unlink()
        print(f"🗑️  Removed {hook_type} hook")
    else:
        print(f"No {hook_type} hook found")
