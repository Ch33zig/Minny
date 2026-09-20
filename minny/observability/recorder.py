"""Where an offline payload goes, and what it is asked afterwards.

Offline mode is not a silent mode. Every payload that would have been sent
to Sentry is built in full, passed through the scrubber, and kept here, so
`data/sentry/` holds the transactions, the error events and the redaction
report that a project would otherwise hold. That is what makes the
instrumentation inspectable without a DSN, and it is also what makes the
timing usable: the span durations are the measurement, not a side effect of
one.

Buffers are capped and drop oldest. A long replay should not be able to turn
observability into the thing that runs out of memory, and the distribution
statistics are kept as running aggregates so the interesting numbers survive
a drop even when the individual payloads do not.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

MAX_TRANSACTIONS = 2000
MAX_EVENTS = 500
MAX_SAMPLES_PER_SPAN = 20000


def _percentile(sorted_values, fraction: float) -> float:
    if not sorted_values:
        return 0.0
    position = min(
        len(sorted_values) - 1, max(0, round(fraction * (len(sorted_values) - 1)))
    )
    return sorted_values[position]


class Recorder:
    def __init__(
        self,
        *,
        max_transactions: int = MAX_TRANSACTIONS,
        max_events: int = MAX_EVENTS,
    ):
        self._lock = threading.Lock()
        self.transactions: list = []
        self.events: list = []
        self.dropped = {"transactions": 0, "events": 0}
        self.samples: dict = {}
        self.max_transactions = max_transactions
        self.max_events = max_events

    # ------------------------------------------------------------ writing

    def record_transaction(self, payload: dict) -> None:
        with self._lock:
            self.transactions.append(payload)
            while len(self.transactions) > self.max_transactions:
                self.transactions.pop(0)
                self.dropped["transactions"] += 1

    def record_event(self, payload: dict) -> None:
        with self._lock:
            self.events.append(payload)
            while len(self.events) > self.max_events:
                self.events.pop(0)
                self.dropped["events"] += 1

    def record_timing(self, name: str, milliseconds: float) -> None:
        """Kept whatever happens to the payload it came from."""
        with self._lock:
            bucket = self.samples.setdefault(
                name, {"count": 0, "total_ms": 0.0, "max_ms": 0.0, "values": []}
            )
            bucket["count"] += 1
            bucket["total_ms"] += milliseconds
            bucket["max_ms"] = max(bucket["max_ms"], milliseconds)
            if len(bucket["values"]) < MAX_SAMPLES_PER_SPAN:
                bucket["values"].append(milliseconds)

    def reset(self) -> None:
        with self._lock:
            self.transactions.clear()
            self.events.clear()
            self.samples.clear()
            self.dropped = {"transactions": 0, "events": 0}

    # ------------------------------------------------------------ reading

    def span_stats(self) -> dict:
        with self._lock:
            out = {}
            for name, bucket in sorted(self.samples.items()):
                values = sorted(bucket["values"])
                out[name] = {
                    "count": bucket["count"],
                    "total_ms": round(bucket["total_ms"], 3),
                    "mean_ms": round(bucket["total_ms"] / bucket["count"], 3),
                    "p50_ms": round(_percentile(values, 0.50), 3),
                    "p95_ms": round(_percentile(values, 0.95), 3),
                    "max_ms": round(bucket["max_ms"], 3),
                }
            return out

    def counts(self) -> dict:
        with self._lock:
            return {
                "transactions": len(self.transactions),
                "events": len(self.events),
                "spans": sum(
                    bucket["count"] for bucket in self.samples.values()
                ),
                "dropped": dict(self.dropped),
            }

    # ----------------------------------------------------------- flushing

    def flush(self, directory: Path, *, meta: dict | None = None) -> dict:
        """Write everything held to `data/sentry/`, atomically per file."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        from minny.observability import scrub

        with self._lock:
            transactions = list(self.transactions)
            events = list(self.events)

        written = {}
        payloads = {
            "transactions.json": transactions,
            "events.json": events,
            "spans.json": {
                "note": (
                    "span timings from this process, the measurement behind "
                    "any performance claim made about it"
                ),
                "spans": self.span_stats(),
                "counts": self.counts(),
            },
            "scrub_report.json": {
                "note": (
                    "every payload in this directory passed through these "
                    "rules before it was written"
                ),
                **scrub.describe(),
            },
        }
        if meta:
            payloads["status.json"] = meta

        for name, payload in payloads.items():
            path = directory / name
            temporary = path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8"
            )
            temporary.replace(path)
            written[name] = str(path)
        return written


RECORDER = Recorder()
