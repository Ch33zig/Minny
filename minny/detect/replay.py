"""Replay engine: one pipeline, paced, with an injection queue (M3).

Three things live here.

`Pipeline` is the detector, the correlator and the rule engine behind one
`feed()` call that returns stream frames. The batch command and the live
stream both drive it, so there is exactly one code path from an event to an
alert to an incident. A streaming result that disagreed with a batch result
would be a bug, and the cheapest way to have no such bug is to have no second
implementation.

`InjectionQueue` is how the red team gets events into a running replay. It is
a thread-safe heap ordered by timestamp, pushed from whichever thread handles
the judge panel request and drained by the replay thread. Injected events
merge into the source stream by `ts` like any other event, so the detector
cannot tell an injected variant from real traffic by position, by ordering or
by anything else. That property is the entire experiment.

`ReplayEngine` walks the merged stream and emits it at a configurable speed,
expressed as simulated log-hours per wall-clock second: at 6.0, one day of
logs takes four seconds. `fast=True` drops the pacing for the evaluation
harness. The engine carries running/paused state, a cursor, an event counter
and a reset that returns to the start of the window, and it can be driven
from another thread through `start`, `pause`, `reset` and `stop`.

Frames match docs/handoff/00-CONTRACTS.md section 12: `event`, `alert`,
`incident` and `replay_state`. `heartbeat` belongs to the transport, not to
the replay, so it is added by whoever serves the stream.
"""

from __future__ import annotations

import heapq
import itertools
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

from minny.baselines.model import Baselines
from minny.detect.correlator import Correlator, build_incident
from minny.detect.events import DetectEvent
from minny.detect.signals import Detector

SECONDS_PER_HOUR = 3600.0

# One simulated hour every sixth of a second. March is 31 days, so the whole
# held-out window runs in about two minutes and the 13-15 March chain lands
# inside the time somebody spends looking at it.
DEFAULT_SPEED_HOURS_PER_SECOND = 6.0

# A replay_state frame every this many events, on top of one for every
# control action. Frequent enough that a progress bar moves, rare enough that
# it is not most of the stream.
STATE_EVERY_EVENTS = 20

# How long the loop sleeps when there is nothing to emit but the replay is
# still following, waiting for an injection or a control call.
IDLE_POLL_S = 0.2

# Checked between events. A stat call per event would be wasteful and a
# reload per minute would be too slow to demo, so the rules file is polled on
# a wall-clock interval.
RULE_RELOAD_INTERVAL_S = 1.0


@dataclass(frozen=True)
class Frame:
    """One stream frame before the transport gives it a sequence number."""

    type: str
    ts: str | None
    data: dict

    def envelope(self, seq: int) -> dict:
        return {"type": self.type, "seq": seq, "ts": self.ts, "data": self.data}


def event_payload(event: DetectEvent, meta: dict | None = None) -> dict:
    """The event as the UI renders it: the section 12 evidence shape.

    Injected events carry their labels here as well, so the front end can
    badge a synthetic line without having to ask another endpoint what it is
    looking at.
    """
    payload = {
        "line": event.line,
        "raw": event.raw,
        "ts": event.ts.isoformat(),
        "user": event.user,
        "ip": event.ip,
        "method": event.method,
        "path": event.path,
        "status": event.status,
        "size": event.size,
    }
    if meta:
        payload.update(meta)
    return payload


def incident_payload(cluster) -> dict:
    """An incident plus the one number the growth animation reads.

    `alert_count` is redundant with `len(alerts)` and it is here on purpose:
    the UI upserts incidents on `incident_id` and animates on this rising
    between frames, and making it read the length of an array to do that
    would be a worse contract.
    """
    incident = build_incident(cluster)
    incident["alert_count"] = len(incident["alerts"])
    return incident


class Pipeline:
    """Detector, rules and correlator behind one call.

    Feeding one event returns every frame that event produced, in the order
    the stream should carry them: the event, then its alerts, then any
    incident that changed. An incident frame is emitted every time the
    incident changes and always carries the same `incident_id`, because the
    growth of a case as evidence arrives is the thing being demonstrated and
    a single frame at the end would show none of it.
    """

    def __init__(self, baselines: Baselines, rules=None):
        self.baselines = baselines
        self.rules = rules
        self.detector = Detector(baselines)
        self.correlator = Correlator()
        self.alerts: list = []
        self.events_seen = 0

    def reset(self) -> None:
        self.detector = Detector(self.baselines)
        self.correlator = Correlator()
        self.alerts = []
        self.events_seen = 0
        if self.rules is not None:
            self.rules.reset()

    def feed(self, event: DetectEvent, meta: dict | None = None) -> list:
        self.events_seen += 1
        frames = [Frame("event", event.ts.isoformat(), event_payload(event, meta))]

        alerts = self.detector.feed(event)
        if self.rules is not None:
            fired = [alert["signal"] for alert in alerts]
            alerts = alerts + self.rules.evaluate(event, self.baselines, fired)

        # Alerts from one event all carry that event's timestamp, so ordering
        # them by alert id here reproduces exactly the order Correlator.run
        # uses on a sorted batch. The two paths build the same clusters and
        # therefore mint the same incident ids.
        alerts.sort(key=lambda alert: alert["alert_id"])

        changed: dict = {}
        for alert in alerts:
            if meta:
                alert.update(meta)
            before = {cluster.incident_id for cluster in self.correlator.clusters}
            incident_id = self.correlator.add(alert)
            self.alerts.append(alert)
            frames.append(Frame("alert", alert["ts"], alert))

            after = {cluster.incident_id for cluster in self.correlator.clusters}
            for absorbed in sorted(before - after):
                # This alert bridged two stories that were separate until
                # now. The UI already has a card for the absorbed one, so it
                # is told where that card went rather than left stale.
                changed.pop(absorbed, None)
                frames.append(
                    Frame(
                        "incident",
                        alert["ts"],
                        {
                            "incident_id": absorbed,
                            "status": "merged",
                            "merged_into": incident_id,
                            "alert_count": 0,
                        },
                    )
                )
            changed[incident_id] = True

        for incident_id in changed:
            cluster = self._cluster(incident_id)
            if cluster is not None:
                payload = incident_payload(cluster)
                frames.append(Frame("incident", payload["last_ts"], payload))
        return frames

    def _cluster(self, incident_id: str):
        for cluster in self.correlator.clusters:
            if cluster.incident_id == incident_id:
                return cluster
        return None

    def incidents(self) -> list:
        return self.correlator.incidents()

    def run(self, events) -> tuple:
        """Batch convenience: feed everything, hand back alerts and incidents."""
        for event in events:
            self.feed(event)
        return self.alerts, self.incidents()


class InjectionQueue:
    """Events pushed into a running replay, ordered by timestamp.

    Thread-safe by construction: every operation takes the lock, and the heap
    never compares two events because the third element of each entry is a
    monotonic counter. Pushing is what the judge panel does, from the request
    thread, while the replay thread is mid-stream.
    """

    def __init__(self, on_push=None):
        self._lock = threading.Lock()
        self._heap: list = []
        self._counter = itertools.count()
        self._pushed = 0
        self._on_push = on_push

    def push(self, events, variant_id=None, synthetic: bool = True) -> int:
        """Add events to the queue. Returns how many were accepted.

        The metadata rides with the event rather than being looked up later,
        so an alert raised by an injected event is labelled at the moment it
        is raised and the incident it joins comes out labelled synthetic
        without anyone having to reconcile two lists afterwards.
        """
        meta = {}
        if synthetic:
            meta["synthetic"] = True
        if variant_id is not None:
            meta["variant_id"] = variant_id

        accepted = 0
        with self._lock:
            for event in events:
                heapq.heappush(
                    self._heap,
                    (event.ts, event.line, next(self._counter), event, dict(meta)),
                )
                accepted += 1
            self._pushed += accepted
        if accepted and self._on_push is not None:
            # Wake the replay thread: the event it is currently sleeping
            # towards may no longer be the next one due.
            self._on_push()
        return accepted

    def peek(self):
        with self._lock:
            return self._heap[0] if self._heap else None

    def pop(self):
        with self._lock:
            return heapq.heappop(self._heap) if self._heap else None

    def clear(self) -> None:
        with self._lock:
            self._heap.clear()

    @property
    def pushed(self) -> int:
        return self._pushed

    def __len__(self) -> int:
        with self._lock:
            return len(self._heap)
