"""Case file and evidence endpoints (track A).

Two routes, wired into the app by `minny/api/app.py` under `/api`:

    GET /api/case_file            the document the UI renders the case from
    GET /api/events?lines=1,2,3   the raw log lines behind any claim

The second one is the evidence drill-down every panel in the UI hangs off, so
it has to be quick and it has to be honest: it returns the bytes from the
original file, never a line re-rendered from parsed fields.

Shapes: docs/handoff/00-CONTRACTS.md sections 7 and 12.
"""

from __future__ import annotations

import functools
import json

import pandas as pd
from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from minny import paths

router = APIRouter()

# The UI drills into one claim at a time. A cap keeps a stray request from
# asking for the whole file through an endpoint meant for evidence.
MAX_LINES = 200

EVIDENCE_COLUMNS = [
    "line",
    "raw",
    "ts",
    "user",
    "ip",
    "method",
    "path",
    "status",
    "size",
]


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code, content={"error": {"code": code, "message": message}}
    )


@functools.lru_cache(maxsize=1)
def _events_by_line() -> pd.DataFrame:
    """Load the evidence columns once and index them for O(1) lookup.

    Lazy rather than at import: a missing parquet file must degrade to a 404
    on one route, not take the router out of the app for every other track.
    """
    frame = pd.read_parquet(
        paths.require(paths.events_path()), columns=EVIDENCE_COLUMNS
    )
    return frame.set_index("line", drop=False)


def _parse_lines(raw: str) -> list[int]:
    """Comma-separated line numbers, order preserved, duplicates dropped."""
    seen: dict[int, None] = {}
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        seen.setdefault(int(token), None)
    return list(seen)


def _serialize(row: pd.Series) -> dict:
    user = row["user"]
    return {
        "line": int(row["line"]),
        "raw": str(row["raw"]),
        # Timezone-aware, always. A naive timestamp here is a four-hour lie in
        # every panel that shows it.
        "ts": pd.Timestamp(row["ts"]).isoformat(),
        # Unknown is null, never the log's "-" and never an empty string.
        "user": None if user is None or pd.isna(user) else str(user),
        "ip": str(row["ip"]),
        "method": str(row["method"]),
        "path": str(row["path"]),
        "status": int(row["status"]),
        "size": int(row["size"]),
    }


@router.get("/case_file")
def get_case_file():
    """The case file exactly as `python -m minny.casefile.build` wrote it."""
    path = paths.case_file_path()
    if not path.exists():
        return _error(
            404,
            "case_file_missing",
            f"{path} has not been built yet. Run `python -m minny.casefile.build`.",
        )
    return json.loads(path.read_text(encoding="utf-8"))


@router.get("/events")
def get_events(lines: str = Query(default="", description="e.g. 168330,168331")):
    """Raw log lines by line number, for the evidence drill-down."""
    if not lines.strip():
        return _error(
            400, "missing_lines", "Pass ?lines= with one or more line numbers."
        )

    try:
        wanted = _parse_lines(lines)
    except ValueError:
        return _error(
            400, "invalid_lines", f"lines must be comma-separated integers, got {lines!r}"
        )

    if len(wanted) > MAX_LINES:
        return _error(
            400,
            "too_many_lines",
            f"{len(wanted)} lines requested, the limit is {MAX_LINES}.",
        )

    try:
        frame = _events_by_line()
    except FileNotFoundError as exc:
        return _error(404, "events_missing", str(exc))

    # A line number that does not exist is simply absent from the response;
    # one bad ID in a batch should not cost the caller the other 199.
    found = [line for line in wanted if line in frame.index]
    return [_serialize(frame.loc[line]) for line in found]
