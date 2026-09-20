"""Spans that behave the same whether or not there is a Sentry project.

The rule that shaped this file: **a call site never branches.** No
`if sentry_enabled`, no `if observability is not None`. `with span("x"):`
either opens a real Sentry span or opens a local one, and either way it
records the duration, because the timing is worth having on a laptop with no
DSN and that is where most of this runs.

A root span closing is a transaction ending. Sentry sends it; offline the
same payload is built, scrubbed and kept for `data/sentry/`. The payload is
the real shape, not a summary, so what a judge reads offline is what the
project would have received.

Nothing here can fail a caller. The context manager's own bookkeeping is
wrapped, and an exception raised inside the block is recorded and then
re-raised unchanged: swallowing it would make observability a behaviour
change, which is the one thing instrumentation must never be.
"""

from __future__ import annotations

import contextlib
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone

from minny.observability import scrub
from minny.observability.recorder import RECORDER

_local = threading.local()

STATUS_OK = "ok"
STATUS_ERROR = "internal_error"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _hex(length: int = 16) -> str:
    return uuid.uuid4().hex[:length]


class Span:
    """One timed region. Cheap enough to open a few thousand times."""

    __slots__ = (
        "name",
        "op",
        "span_id",
        "trace_id",
        "parent_id",
        "data",
        "status",
        "started_at",
        "start_iso",
        "end_iso",
        "duration_ms",
        "children",
        "counters",
        "_sentry",
    )

    def __init__(self, name: str, op: str, trace_id: str, parent_id: str | None):
        self.name = name
        self.op = op
        self.span_id = _hex(16)
        self.trace_id = trace_id
        self.parent_id = parent_id
        self.data: dict = {}
        self.counters: dict = {}
        self.status = STATUS_OK
        self.started_at = time.perf_counter()
        self.start_iso = _now_iso()
        self.end_iso: str | None = None
        self.duration_ms = 0.0
        self.children: list = []
        self._sentry = None

    def set_data(self, key: str, value) -> None:
        """Context, never a payload. Unbounded labels are the anti-pattern."""
        try:
            self.data[key] = value
            if self._sentry is not None:
                self._sentry.set_data(key, value)
        except Exception:  # noqa: BLE001 - instrumentation is never fatal
            pass

    def update(self, **data) -> None:
        for key, value in data.items():
            self.set_data(key, value)

    def add(self, key: str, amount: float = 1.0) -> None:
        """Accumulate inside a hot loop without opening a span per iteration.

        A per-event span on a replay of 180,800 events would cost more than
        the thing it measures, so the loop adds to a counter on the span it
        is already inside and the totals land in the payload at close.
        """
        try:
            self.counters[key] = self.counters.get(key, 0.0) + amount
        except Exception:  # noqa: BLE001
            pass

    def payload(self) -> dict:
        data = dict(self.data)
        for key, value in self.counters.items():
            data[key] = round(value, 6) if isinstance(value, float) else value
        return {
            "span_id": self.span_id,
            "parent_span_id": self.parent_id,
            "trace_id": self.trace_id,
            "op": self.op,
            "description": self.name,
            "start_timestamp": self.start_iso,
            "timestamp": self.end_iso,
            "status": self.status,
            "data": data,
        }


class _NullSpan:
    """Handed out when the machinery itself failed. Accepts everything."""

    name = "unavailable"
    data: dict = {}
    counters: dict = {}
    status = STATUS_OK
    duration_ms = 0.0

    def set_data(self, key, value):
        pass

    def update(self, **data):
        pass

    def add(self, key, amount=1.0):
        pass


NULL_SPAN = _NullSpan()


def _stack() -> list:
    stack = getattr(_local, "stack", None)
    if stack is None:
        stack = []
        _local.stack = stack
    return stack


def current():
    """The innermost open span, or a sink that accepts everything."""
    stack = _stack()
    return stack[-1] if stack else NULL_SPAN


@contextlib.contextmanager
def span(name: str, op: str | None = None, **data):
    """Open one span. Safe anywhere, including inside a request handler."""
    # The submodule, not the `init` function the package re-exports.
    from minny.observability.init import state as _state

    state = _state()
    opened = None
    try:
        stack = _stack()
        parent = stack[-1] if stack else None
        trace_id = parent.trace_id if parent else _hex(32)
        opened = Span(name, op or name.split(".")[0], trace_id, parent.span_id if parent else None)
        opened.update(**data)
        if state["mode"] == "sentry":
            opened._sentry = _open_sentry_span(name, op, parent is None)
        stack.append(opened)
    except Exception:  # noqa: BLE001 - a broken span is not a broken program
        opened = None

    handle = opened or NULL_SPAN
    try:
        yield handle
    except BaseException as exc:
        if opened is not None:
            opened.status = STATUS_ERROR
            opened.set_data("error", f"{type(exc).__name__}: {exc}")
        if isinstance(exc, Exception):
            capture_exception(exc, span=opened)
        _close(opened)
        raise
    else:
        _close(opened)


def _open_sentry_span(name: str, op: str | None, is_root: bool):
    try:
        import sentry_sdk

        if is_root:
            context = sentry_sdk.start_transaction(
                name=name, op=op or name.split(".")[0]
            )
        else:
            context = sentry_sdk.start_span(op=op or name.split(".")[0], description=name)
        return context.__enter__()
    except Exception:  # noqa: BLE001 - the local span still works
        return None


def _close(opened) -> None:
    if opened is None:
        return
    try:
        stack = _stack()
        if stack and stack[-1] is opened:
            stack.pop()
        opened.duration_ms = (time.perf_counter() - opened.started_at) * 1000.0
        opened.end_iso = _now_iso()
        RECORDER.record_timing(opened.name, opened.duration_ms)

        if opened._sentry is not None:
            with contextlib.suppress(Exception):
                opened._sentry.__exit__(None, None, None)

        parent = stack[-1] if stack else None
        if parent is not None:
            parent.children.append(opened)
            return
        _deliver_transaction(opened)
    except Exception:  # noqa: BLE001
        pass


def _flatten(root: Span) -> list:
    out = []
    pending = list(root.children)
    while pending:
        node = pending.pop(0)
        out.append(node)
        pending.extend(node.children)
    return out


def _deliver_transaction(root: Span) -> None:
    """A closed root span is a finished transaction."""
    # The submodule, not the `init` function the package re-exports.
    from minny.observability.init import state as _state

    state = _state()
    if state["mode"] == "sentry":
        # The SDK already sent its own transaction through the same
        # before_send_transaction hook. Sending a second copy would double
        # the quota and halve the trust in the numbers.
        return

    payload = {
        "type": "transaction",
        "event_id": _hex(32),
        "transaction": root.name,
        "platform": "python",
        "environment": state["environment"],
        "release": state["release"],
        "server_name": None,
        "start_timestamp": root.start_iso,
        "timestamp": root.end_iso,
        "contexts": {
            "trace": {
                "trace_id": root.trace_id,
                "span_id": root.span_id,
                "op": root.op,
                "status": root.status,
                "data": dict(root.data, **root.counters),
            }
        },
        "measurements": {
            "duration": {"value": round(root.duration_ms, 3), "unit": "millisecond"}
        },
        "tags": {"service": state["service"], "mode": "offline"},
        "spans": [child.payload() for child in _flatten(root)],
    }
    cleaned = scrub.before_send_transaction(payload)
    if cleaned is not None:
        RECORDER.record_transaction(cleaned)


# ------------------------------------------------------------- breadcrumbs


def breadcrumb(message: str, *, category: str = "minny", level: str = "info", **data):
    """A breadcrumb is scrubbed on the way in, not only on the way out."""
    from minny.observability.init import state as _state

    try:
        crumb = {
            "type": "default",
            "category": category,
            "level": level,
            "message": message,
            "timestamp": _now_iso(),
            "data": data,
        }
        cleaned = scrub.before_breadcrumb(crumb)
        if cleaned is None:
            return
        if _state()["mode"] == "sentry":
            import sentry_sdk

            sentry_sdk.add_breadcrumb(cleaned)
    except Exception:  # noqa: BLE001
        pass


# ------------------------------------------------------------- exceptions


def capture_exception(exc: BaseException, *, span=None, **data) -> None:
    """Record an error without ever raising one of its own."""
    # The submodule, not the `init` function the package re-exports.
    from minny.observability.init import state as _state

    state = _state()
    try:
        if state["mode"] == "sentry":
            import sentry_sdk

            sentry_sdk.capture_exception(exc)
            return

        frames = []
        for frame in traceback.extract_tb(exc.__traceback__)[-10:]:
            # Filename, line and function only. Local variables are where a
            # username would ride along into an error report.
            frames.append(
                {
                    "filename": frame.filename,
                    "lineno": frame.lineno,
                    "function": frame.name,
                }
            )
        holder = span if span is not None else current()
        payload = {
            "event_id": _hex(32),
            "level": "error",
            "platform": "python",
            "timestamp": _now_iso(),
            "environment": state["environment"],
            "release": state["release"],
            "tags": {"service": state["service"], "mode": "offline"},
            "exception": {
                "values": [
                    {
                        "type": type(exc).__name__,
                        "value": str(exc),
                        "mechanism": {"type": "minny", "handled": True},
                        "stacktrace": {"frames": frames},
                    }
                ]
            },
            "contexts": {
                "trace": {
                    "trace_id": getattr(holder, "trace_id", None),
                    "span_id": getattr(holder, "span_id", None),
                    "op": getattr(holder, "op", None),
                }
            },
            "extra": dict(data),
        }
        cleaned = scrub.before_send(payload)
        if cleaned is not None:
            RECORDER.record_event(cleaned)
    except Exception:  # noqa: BLE001
        pass
