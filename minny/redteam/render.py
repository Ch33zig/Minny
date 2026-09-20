"""Turn abstract attack steps into Common Log Format lines (milestone M4).

Two rules make the output survive inspection, and both are structural rather
than stylistic:

* Every line is a rewrite of a **real** line. We match a real event on
  (template, status), keep its method, ident field and protocol token, and
  overwrite only ip, user, ts, path, status and size. Nothing about the
  skeleton is reconstructed from the format spec, so nothing about it can
  drift from the format spec.
* Every size comes from A's size_table.json. Fixed pairs take the constant;
  variable pairs sample uniformly inside the real [min, max]. Uniform is not
  a guess — the real forum-view, dashboard, metrics and asset sizes are flat
  across their ranges, so any other shape would stand out in a histogram.

The one thing the brief got wrong is the timezone. It predicted -0500 for
dates before 8 March 2026, but all 180,800 real lines carry -0400, including
August and December ones. Rendering a winter offset would make every
synthetic March line identifiable at a glance, so the offset is a constant
and a test pins it against the dataset.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone

from minny.parser import LINE_RE
from minny.redteam.catalog import Catalog, template_of

LOG_UTC_OFFSET = timezone(timedelta(hours=-4))

# strftime("%b") is locale dependent and this has to be byte-identical to the
# real file on any machine that runs the demo.
MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)

# Injected IDs start here so a synthetic event can never collide with a real
# one. 180,800 is the whole dataset; see 00-CONTRACTS.md section 8.
FIRST_INJECTED_LINE = 180_801

BUSINESS_START = time(9, 0)
BUSINESS_END = time(17, 0)


@dataclass(frozen=True)
class Step:
    """One logical action, before it has a timestamp, a size or a line ID."""

    kind: str
    actor: str
    ip: str
    path: str
    status: int
    gap_s: int  # seconds since the previous step
    phase: str


@dataclass(frozen=True)
class RenderedLine:
    line: int
    raw: str
    ts: datetime
    kind: str
    phase: str


class SizeTable:
    """size_table.json, resolved by exact path and then by template.

    Resolving by template matters for the two synthetic-only shapes. A
    variant that escalates through post 1063 needs a size for
    /assets/avatar_1063.png, which never occurs; the avatar template occurs
    once, at 1205 bytes, so 1205 is the only honest answer. Inventing a
    plausible number instead is exactly the forgery this table exists to
    prevent.
    """

    def __init__(self, table: dict) -> None:
        self._fixed = table["by_path"]
        self._variable = table["variable_size_paths"]
        self._by_template = self._merge_by_template()

    def _merge_by_template(self) -> dict[str, dict[str, list[int]]]:
        merged: dict[str, dict[str, list[int]]] = {}
        for path, by_status in self._fixed.items():
            template = template_of(path)
            for status, size in by_status.items():
                merged.setdefault(template, {}).setdefault(status, []).extend(
                    [size, size]
                )
        for path, by_status in self._variable.items():
            template = template_of(path)
            for status, bounds in by_status.items():
                merged.setdefault(template, {}).setdefault(status, []).extend(bounds)
        return {
            template: {status: [min(v), max(v)] for status, v in by_status.items()}
            for template, by_status in merged.items()
        }

    def bounds(self, path: str, status: int) -> tuple[int, int] | None:
        """Inclusive [low, high] of sizes the real data shows for this pair."""
        base = path.split("?", 1)[0]
        key = str(status)
        fixed = self._fixed.get(base, {}).get(key)
        if fixed is not None:
            return (fixed, fixed)
        variable = self._variable.get(base, {}).get(key)
        if variable is not None:
            return (variable[0], variable[-1])
        by_template = self._by_template.get(template_of(base), {}).get(key)
        if by_template is not None:
            return (by_template[0], by_template[1])
        return None

    def sample(self, path: str, status: int, rng: random.Random) -> int:
        bounds = self.bounds(path, status)
        if bounds is None:
            raise KeyError(
                f"size_table.json has no size for ({path!r}, {status}); "
                "rendering it would mean inventing one"
            )
        low, high = bounds
        return low if low == high else rng.randint(low, high)

    def is_consistent(self, path: str, status: int, size: int) -> bool:
        bounds = self.bounds(path, status)
        if bounds is None:
            return False
        return bounds[0] <= size <= bounds[1]


def format_ts(ts: datetime) -> str:
    """`15/Mar/2026:11:26:59 -0400`, the dataset's exact spelling."""
    offset = ts.utcoffset() or timedelta(0)
    total = int(offset.total_seconds())
    sign = "-" if total < 0 else "+"
    hours, minutes = divmod(abs(total) // 60, 60)
    return (
        f"{ts.day:02d}/{MONTHS[ts.month - 1]}/{ts.year}:"
        f"{ts.hour:02d}:{ts.minute:02d}:{ts.second:02d} "
        f"{sign}{hours:02d}{minutes:02d}"
    )


def rewrite(
    template_raw: str,
    *,
    ip: str,
    user: str,
    ts: datetime,
    path: str,
    status: int,
    size: int,
) -> str:
    """Rewrite a real line, keeping its method, ident field and protocol."""
    match = LINE_RE.match(template_raw)
    if match is None:  # pragma: no cover - the pool comes from the parser
        raise ValueError(f"template line does not parse: {template_raw!r}")
    _ip, ident, _user, _ts, method, _path, protocol, _status, _size = match.groups()
    return (
        f"{ip} {ident} {user} [{format_ts(ts)}] "
        f'"{method} {path} {protocol}" {status} {size}'
    )


def _open_of_business(day, tzinfo, jitter: int) -> datetime:
    """09:00 plus a few minutes.

    Without the jitter every business-hours variant opens at exactly
    09:00:00, and a run of lines landing on the hour to the second is the
    single most obvious tell a rendered corpus can carry.
    """
    return datetime.combine(day, BUSINESS_START, tzinfo=tzinfo) + timedelta(
        seconds=jitter
    )


def _next_business_slot(ts: datetime, jitter: int) -> datetime:
    """Push a timestamp into the next 09:00-17:00 weekday slot."""
    while True:
        if ts.weekday() >= 5:
            ts = _open_of_business(ts.date() + timedelta(days=1), ts.tzinfo, jitter)
            continue
        if ts.time() < BUSINESS_START:
            ts = _open_of_business(ts.date(), ts.tzinfo, jitter)
            continue
        if ts.time() >= BUSINESS_END:
            ts = _open_of_business(ts.date() + timedelta(days=1), ts.tzinfo, jitter)
            continue
        return ts


def schedule(
    start: datetime,
    gaps: list[int],
    *,
    business_hours: bool = False,
    rng: random.Random | None = None,
) -> list[datetime]:
    """Lay gaps out from a start time, strictly increasing.

    Under `business_hours` a gap that would run past 17:00 or onto a weekend
    rolls to 09:00 on the next weekday instead of being dropped. That only
    ever makes a gap longer, which is why the critic checks `slow_guess` and
    `delay_gap` as lower bounds: the operator's purpose is defeating a short
    correlation window, and a longer gap defeats it harder.
    """
    def jitter() -> int:
        return rng.randint(60, 2400) if rng is not None else 0

    stamps: list[datetime] = []
    current = _next_business_slot(start, jitter()) if business_hours else start
    for index, gap in enumerate(gaps):
        if index:
            current = current + timedelta(seconds=max(1, gap))
            if business_hours:
                current = _next_business_slot(current, jitter())
        stamps.append(current)

    for index in range(1, len(stamps)):
        if stamps[index] <= stamps[index - 1]:
            stamps[index] = stamps[index - 1] + timedelta(seconds=1)
    return stamps


def render(
    steps: list[Step],
    *,
    catalog: Catalog,
    size_table: SizeTable,
    start: datetime,
    first_line: int,
    rng: random.Random,
    business_hours: bool = False,
) -> list[RenderedLine]:
    stamps = schedule(
        start,
        [step.gap_s for step in steps],
        business_hours=business_hours,
        rng=rng,
    )

    lines: list[RenderedLine] = []
    for offset, (step, ts) in enumerate(zip(steps, stamps)):
        key = (template_of(step.path), step.status)
        template = catalog.line_templates.get(key)
        if template is None:
            raise KeyError(
                f"no real line to clone for {key}; a synthetic shape with no "
                "real precedent is exactly what the blind test catches"
            )
        size = size_table.sample(step.path, step.status, rng)
        raw = rewrite(
            template.raw,
            ip=step.ip,
            user=step.actor,
            ts=ts,
            path=step.path,
            status=step.status,
            size=size,
        )
        lines.append(
            RenderedLine(
                line=first_line + offset,
                raw=raw,
                ts=ts,
                kind=step.kind,
                phase=step.phase,
            )
        )
    return lines
