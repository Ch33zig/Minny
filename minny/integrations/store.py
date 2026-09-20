"""Where integration output is kept, and what happens when writing fails.

Three small stores, all of them optional:

* `data/email_evidence.json`, the mailbox evidence the case file and the
  correlator read. Written by the Gmail sync.
* `data/github_pr_artifacts.json`, the exact pull request body that was, or
  would have been, posted for each rule. Mock mode makes this the artifact
  the UI shows instead of a link.
* An in-process delivery log, so the UI can say that an alert failed to send
  without anybody concluding that the incident failed to open.

Delivery status is deliberately separate from detection status. An incident
is found whether or not Slack accepted the message, so nothing in here can
change an incident and nothing in here can fail loudly enough to matter.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from minny import paths

logger = logging.getLogger("minny.integrations")

# Enough history for the demo and for a judge asking what happened, and
# small enough that a long-running process never grows on it.
MAX_DELIVERIES = 50

_deliveries: deque[dict] = deque(maxlen=MAX_DELIVERIES)
_lock = threading.Lock()


def pr_artifacts_path() -> Path:
    return paths.data_dir() / "github_pr_artifacts.json"


def read_json(path: Path) -> Any | None:
    """Read a JSON artifact, or report nothing. A corrupt file is nothing."""
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - a bad artifact is a missing one
        logger.warning("could not read %s: %s", path, exc)
        return None


def write_json(path: Path, payload: Any) -> bool:
    """Write an artifact, and carry on if the disk says no.

    Returns whether it landed. A failed write means the UI shows a stale or
    empty integration panel, never a failed request.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(text, encoding="utf-8")
        temp.replace(path)
        return True
    except Exception as exc:  # noqa: BLE001 - never fatal
        logger.warning("could not write %s: %s", path, exc)
        return False


def read_email_store() -> dict | None:
    store = read_json(paths.email_evidence_path())
    return store if isinstance(store, dict) else None


def write_email_store(store: dict) -> bool:
    return write_json(paths.email_evidence_path(), store)


def read_pr_artifacts() -> dict:
    artifacts = read_json(pr_artifacts_path())
    return artifacts if isinstance(artifacts, dict) else {}


def upsert_pr_artifact(rule_id: str, artifact: dict) -> bool:
    """One artifact per rule, replaced in place.

    Keyed by rule id rather than appended, because clicking the button twice
    for the same rule is one intent and must not read as two pull requests.
    """
    artifacts = read_pr_artifacts()
    artifacts[rule_id] = artifact
    return write_json(pr_artifacts_path(), artifacts)


def record_delivery(entry: dict) -> dict:
    """Log one outbound attempt. Detection never reads this."""
    stamped = {"at": datetime.now(timezone.utc).isoformat(), **entry}
    with _lock:
        _deliveries.appendleft(stamped)
    return stamped


def deliveries(limit: int = MAX_DELIVERIES) -> list[dict]:
    with _lock:
        return list(_deliveries)[:limit]


def last_delivery(capability: str) -> dict | None:
    with _lock:
        for entry in _deliveries:
            if entry.get("capability") == capability:
                return entry
    return None


def reset_deliveries() -> None:
    """For tests. Nothing in the application clears the log."""
    with _lock:
        _deliveries.clear()
