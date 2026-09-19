"""Canonical event parser for the access log (milestone M0).

Turns Apache Common Log Format lines into the columnar contract described in
docs/handoff/00-CONTRACTS.md section 1. Every downstream track reads the
output of this module and nothing else, so the asserts here are load bearing:
a silently dropped line becomes a silently wrong case file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

EXPECTED_ROWS = 180_800

LINE_RE = re.compile(
    r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\S+)$'
)

CLF_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# The template normalisation list is a contract. B keys baselines on templates
# and C keys mutations on them, so adding a fourth family after the contract
# freeze breaks both of them silently.
TEMPLATE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^/intranet/forum/view/(\d+)$"), "/intranet/forum/view/{id}"),
    (re.compile(r"^/intranet/forum/edit/(\d+)$"), "/intranet/forum/edit/{id}"),
    (re.compile(r"^/assets/avatar_(\d+)\.png$"), "/assets/avatar_{id}.png"),
)


@dataclass(frozen=True)
class Event:
    """One parsed log line. `line` is the universal event ID."""

    line: int
    raw: str
    ip: str
    user: str | None
    ts: datetime
    method: str
    path: str
    base: str
    query: dict[str, str]
    status: int
    size: int
    template: str
    obj_id: int | None


def normalize_template(base: str) -> tuple[str, int | None]:
    """Collapse numeric object IDs so per-user baselines are meaningful.

    Without this, every forum post is its own template and "user X has never
    requested this template" fires on ordinary browsing.
    """
    for pattern, template in TEMPLATE_RULES:
        match = pattern.match(base)
        if match:
            return template, int(match.group(1))
    return base, None


def parse_line(line_no: int, raw: str) -> Event:
    match = LINE_RE.match(raw)
    if match is None:
        raise ValueError(f"line {line_no} does not match the CLF pattern: {raw!r}")

    ip, _ident, user, ts_text, method, path, _proto, status, size = match.groups()

    split = urlsplit(path)
    base = split.path
    query = dict(parse_qsl(split.query, keep_blank_values=True))
    template, obj_id = normalize_template(base)

    return Event(
        line=line_no,
        raw=raw,
        ip=ip,
        # The log writes "-" for an unauthenticated request. Unknown is None,
        # never the string "-", or every consumer has to special case it.
        user=None if user == "-" else user,
        ts=datetime.strptime(ts_text, CLF_TIME_FORMAT),
        method=method,
        path=path,
        base=base,
        query=query,
        status=int(status),
        # A "-" size means no body was sent.
        size=0 if size == "-" else int(size),
        template=template,
        obj_id=obj_id,
    )


def parse_file(path: str | Path) -> list[Event]:
    """Parse every line, or raise. Partial success is not a useful outcome."""
    events: list[Event] = []
    failures: list[tuple[int, str]] = []

    with open(path, "r", encoding="utf-8", errors="strict") as handle:
        for line_no, raw in enumerate(handle, start=1):
            raw = raw.rstrip("\n").rstrip("\r")
            if not raw:
                continue
            try:
                events.append(parse_line(line_no, raw))
            except ValueError as exc:  # noqa: PERF203 - we want every failure
                failures.append((line_no, str(exc)))

    if failures:
        preview = "\n".join(f"  {no}: {msg}" for no, msg in failures[:5])
        raise ValueError(
            f"{len(failures)} line(s) failed to parse. First few:\n{preview}"
        )

    _assert_event_ids_are_contiguous(events)
    return events


def _assert_event_ids_are_contiguous(events: list[Event]) -> None:
    """Evidence is cited by line number, so a gap silently misattributes it."""
    for index, event in enumerate(events, start=1):
        if event.line != index:
            raise AssertionError(
                f"event IDs must be contiguous from 1; position {index} "
                f"carries line {event.line}"
            )
