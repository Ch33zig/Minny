"""Tracing and error reporting that works with or without a Sentry project.

Import this and instrument. There is no branch at the call site:

    from minny import observability as obs

    with obs.span("replay.evaluate", variant_id=variant_id) as active:
        active.set_data("events", len(stream))

With `SENTRY_BACKEND_DSN` set, that opens a real Sentry transaction and span.
Without it, nothing is sent anywhere, the same payload is built and scrubbed,
and it is written to `data/sentry/` where it can be read. Either way the
duration is recorded, because the timing is the point and most of this runs
on a laptop with no DSN.

Everything is scrubbed before it leaves: no raw log lines, no usernames, no
addresses, no mailbox content. See `minny.observability.scrub` for the rules
and the order they run in.
"""

from __future__ import annotations

from minny.observability.init import (
    enabled,
    flush,
    init,
    offline,
    reset_for_tests,
    state,
    status,
)
from minny.observability.recorder import RECORDER
from minny.observability.scrub import register_identifiers
from minny.observability.spans import (
    breadcrumb,
    capture_exception,
    current,
    span,
)

__all__ = [
    "RECORDER",
    "breadcrumb",
    "capture_exception",
    "current",
    "enabled",
    "flush",
    "init",
    "offline",
    "register_identifiers",
    "reset_for_tests",
    "span",
    "state",
    "status",
]
