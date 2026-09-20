"""The event shape the signals see.

Signals are pure functions and they run 180,800 times, so they must never have
to ask what kind of null they are holding. Parquet hands back pandas NA for a
missing obj_id and widens the query map into a struct where an absent
parameter is a None value; both are normalised away here, once, at the
boundary. Everything downstream sees plain Python and `None` means unknown.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator

import pandas as pd


@dataclass(frozen=True)
class DetectEvent:
    """One log line, as the detector reads it. `line` is the event ID."""

    line: int
    ts: datetime
    ip: str
    user: str | None
    method: str
    path: str
    base: str
    query: dict
    status: int
    size: int
    template: str
    obj_id: int | None
    raw: str = ""

    @property
    def params(self) -> frozenset:
        return frozenset(self.query)


def _clean(value):
    """pandas NA, NaN and None all mean the same thing to a signal."""
    if value is None or value is pd.NA:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    return value


def from_row(row) -> DetectEvent:
    obj_id = _clean(getattr(row, "obj_id", None))
    query = getattr(row, "query", None) or {}
    return DetectEvent(
        line=int(row.line),
        ts=row.ts.to_pydatetime() if hasattr(row.ts, "to_pydatetime") else row.ts,
        ip=row.ip,
        user=_clean(row.user),
        method=row.method,
        path=row.path,
        base=row.base,
        # An absent parameter is dropped rather than carried as None, so
        # `set(event.query)` is exactly the parameter names that were sent.
        query={k: v for k, v in query.items() if v is not None},
        status=int(row.status),
        size=int(row.size),
        template=row.template,
        obj_id=int(obj_id) if obj_id is not None else None,
        raw=getattr(row, "raw", "") or "",
    )


def from_frame(frame: pd.DataFrame) -> Iterator[DetectEvent]:
    """Replay order is timestamp order, then line order to break ties.

    The correlator windows on wall-clock time, so an out-of-order feed would
    silently widen or split an incident.
    """
    ordered = frame.sort_values(["ts", "line"], kind="stable")
    for row in ordered.itertuples(index=False):
        yield from_row(row)


def merged(*streams: Iterable[DetectEvent]) -> Iterator[DetectEvent]:
    """Interleave several event streams by timestamp.

    This is the hook the replay engine and the red team's injection queue will
    share: injected variants must arrive in time order or the detector can
    tell them apart by position alone, which would make the stress test
    meaningless.
    """
    pooled = [event for stream in streams for event in stream]
    pooled.sort(key=lambda event: (event.ts, event.line))
    return iter(pooled)
