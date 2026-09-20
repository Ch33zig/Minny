"""Where the shared data artifacts live.

The dataset is not in version control. This repository is public and the logs
are competition material, so `data/` is gitignored and shared out of band,
verified by SHA-256.

That creates one wrinkle: tracks are developed in parallel git worktrees, and
a gitignored directory does not follow a worktree. So every module resolves
the data directory through here rather than hardcoding a relative path. Set
MINNY_DATA_DIR to the main checkout's data directory when working in a
worktree:

    export MINNY_DATA_DIR=C:/Users/sonaw/Naman/Projects/Minny/data
"""

from __future__ import annotations

import os
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    override = os.environ.get("MINNY_DATA_DIR")
    return Path(override) if override else _REPO_ROOT / "data"


def logs_path() -> Path:
    """The raw access log. Present only where it was copied in."""
    return data_dir() / "logs.txt"


def events_path() -> Path:
    """Canonical parsed events. Rebuild with `python -m minny.build_events`."""
    return data_dir() / "events.parquet"


def size_table_path() -> Path:
    return data_dir() / "size_table.json"


def access_matrix_path() -> Path:
    return data_dir() / "access_matrix.json"


def baselines_path() -> Path:
    return data_dir() / "baselines.json"


def case_file_path() -> Path:
    return data_dir() / "case_file.json"


def metrics_path() -> Path:
    return data_dir() / "metrics.json"


def email_evidence_path() -> Path:
    return data_dir() / "email_evidence.json"


def rules_path() -> Path:
    """Detection rules written by the blue agent.

    These are source, not data: they are committed, reviewed in a pull
    request and follow a worktree, so they resolve against the repository
    rather than MINNY_DATA_DIR. MINNY_RULES_PATH overrides the location for a
    test that needs its own file.
    """
    override = os.environ.get("MINNY_RULES_PATH")
    if override:
        return Path(override)
    return _REPO_ROOT / "detection-rules" / "rules.yaml"


def require(path: Path) -> Path:
    """Fail with the command that produces the missing artifact."""
    if not path.exists():
        raise FileNotFoundError(
            f"{path} is missing. If you are in a worktree, set MINNY_DATA_DIR "
            f"to the main checkout's data directory. Otherwise rebuild with "
            f"`python -m minny.build_events`."
        )
    return path
