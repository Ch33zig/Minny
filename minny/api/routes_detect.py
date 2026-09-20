"""Detector routes (track B), mounted under /api by minny.api.app.

Routes are declared without the /api prefix because the application adds it.
Declaring it here too would serve them at /api/api and nobody would notice
until the UI was already wired up.

Everything served here is a file on disk written by `python -m minny.detect.run`,
re-read when its mtime changes. That means a replay in one terminal is visible
to the API in another without a restart, which is the difference between
iterating on signals and restarting the demo.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from minny import paths

router = APIRouter(tags=["detect"])

_cache: dict = {}


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status, content={"error": {"code": code, "message": message}}
    )


def _load(path: Path):
    """Read a JSON artifact, reusing the parse until the file changes."""
    key = str(path)
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        _cache.pop(key, None)
        return None
    cached = _cache.get(key)
    if cached and cached[0] == stamp:
        return cached[1]
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    _cache[key] = (stamp, payload)
    return payload


def _missing(path: Path, command: str) -> JSONResponse:
    return _error(
        503,
        "artifact_missing",
        f"{path.name} has not been built. Run `{command}`. If you are in a "
        f"worktree, set MINNY_DATA_DIR to the main checkout's data directory.",
    )


def _incidents_path() -> Path:
    return paths.data_dir() / "incidents.json"


def _alerts_path() -> Path:
    return paths.data_dir() / "alerts.json"


@router.get("/baselines")
def get_baselines():
    """The fitted baseline, exactly as written. C tests variants against it."""
    document = _load(paths.baselines_path())
    if document is None:
        return _missing(paths.baselines_path(), "python -m minny.baselines.build")
    return document


@router.get("/incidents")
def list_incidents():
    """Newest first, which is the order the file is already written in."""
    incidents = _load(_incidents_path())
    if incidents is None:
        return _missing(_incidents_path(), "python -m minny.detect.run")
    return sorted(incidents, key=lambda inc: inc.get("opened_ts", ""), reverse=True)


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    """One incident with its alerts inlined.

    `alerts` keeps the contract's array of IDs and `alerts_expanded` carries
    the objects. Adding a field is free; changing the meaning of one is not.
    """
    incidents = _load(_incidents_path())
    if incidents is None:
        return _missing(_incidents_path(), "python -m minny.detect.run")

    match = next(
        (inc for inc in incidents if inc.get("incident_id") == incident_id), None
    )
    if match is None:
        return _error(404, "not_found", f"No incident {incident_id}")

    alerts = _load(_alerts_path()) or []
    by_id = {alert["alert_id"]: alert for alert in alerts}
    return {
        **match,
        "alerts_expanded": [
            by_id[alert_id] for alert_id in match.get("alerts", []) if alert_id in by_id
        ],
    }
