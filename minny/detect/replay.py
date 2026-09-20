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

from minny import observability as obs
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

# A wait shorter than this is not worth taking. A Windows timer wakes on
# roughly a 15 ms tick, so asking for 80 nanoseconds costs 15 milliseconds
# and a fast replay spends all its time in the scheduler rather than in the
# detector. Below the floor the event is simply due now.
MIN_SLEEP_S = 0.002

# How far behind its own schedule the replay will try to catch up. Each
# event's deadline is measured from the previous event's deadline rather
# than from the moment the previous one actually came out, so a wait that
# overran is absorbed by the next gap instead of being added to it. Without
# that, every overshoot compounds: measured over two days of March at the
# default speed, the loop asked for 7,040 ms of sleep and spent 11,907 ms,
# because a timer that rounds every request up to a 16 ms tick overshoots by
# about 9.8 ms each time and 496 waits carried the error forward. The clamp
# is what stops a paused or stalled replay from sprinting through a backlog
# when it resumes; past this much lateness the schedule restarts from now.
MAX_CATCHUP_S = 0.25

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
        with obs.span("replay.evaluate", mode="batch") as active:
            count = 0
            for event in events:
                count += 1
                self.feed(event)
            incidents = self.incidents()
            active.update(
                events=count, alerts=len(self.alerts), incidents=len(incidents)
            )
            return self.alerts, incidents


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


def _iso(value) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else None


class ReplayEngine:
    """Walks a window of events at a chosen speed and emits stream frames.

    Speed is simulated log-hours per wall-clock second, so the number means
    the same thing whether the window is an hour or seven months. `fast=True`
    removes the pacing entirely for the evaluation harness, which replays
    thousands of variants and cares only about what was detected.

    Control comes from another thread. `start`, `pause`, `reset`, `stop`,
    `set_speed` and `inject` all just set state and wake the loop, so the HTTP
    handler never blocks on a replay and a judge clicking pause sees it stop
    inside a frame rather than at the end of a long sleep.
    """

    def __init__(
        self,
        source_factory,
        baselines: Baselines,
        rules=None,
        speed_hours_per_second: float = DEFAULT_SPEED_HOURS_PER_SECOND,
        fast: bool = False,
        max_gap_s: float | None = None,
        start_ts: datetime | None = None,
        end_ts: datetime | None = None,
        sink=None,
        clock=time.monotonic,
    ):
        self._source_factory = source_factory
        self.baselines = baselines
        self.rules = rules
        self.pipeline = Pipeline(baselines, rules=rules)
        self.speed = float(speed_hours_per_second)
        self.fast = bool(fast)
        # A quiet stretch of log should not be a quiet stretch of demo. With
        # this set, a gap longer than the clamp is crossed in the clamp's
        # wall-clock time and the cursor still jumps the whole way, so the
        # timeline stays truthful while the screen keeps moving.
        self.max_gap_s = max_gap_s
        self.sink = sink
        self.clock = clock

        self._from = start_ts
        self._to = end_ts
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self.queue = InjectionQueue(on_push=self._wake.set)

        self._source = None
        self._pending = None
        self._running = False
        self._stopped = False
        self._reset_requested = False
        self._alive = False
        self._finished = False
        self._started_once = False
        self._last_sim: datetime | None = None
        self._chosen_key = None
        self._due_at = 0.0
        self._rules_checked_at = 0.0

        self.cursor: datetime | None = start_ts
        self.events_emitted = 0

    # ------------------------------------------------------------- factory

    @classmethod
    def from_events(cls, events, baselines: Baselines, **kwargs) -> "ReplayEngine":
        """Build over an in-memory list, which is what the tests replay."""
        pooled = sorted(events, key=lambda event: (event.ts, event.line))

        def factory(start, end):
            return iter(
                [
                    event
                    for event in pooled
                    if (start is None or event.ts >= start)
                    and (end is None or event.ts < end)
                ]
            )

        return cls(factory, baselines, **kwargs)

    # --------------------------------------------------------------- state

    def state(self) -> dict:
        """The `replay_state` payload of section 12, plus what the UI asked for."""
        rules = self.rules
        return {
            "running": self._running,
            "speed_hours_per_second": self.speed,
            "cursor_ts": _iso(self.cursor),
            "events_emitted": self.events_emitted,
            "from": _iso(self._from),
            "to": _iso(self._to),
            "mode": "fast" if self.fast else "paced",
            "max_gap_s": self.max_gap_s,
            "finished": self._finished,
            "alerts_emitted": len(self.pipeline.alerts),
            "incidents": len(self.pipeline.correlator.clusters),
            "injected": self.queue.pushed,
            "injected_pending": len(self.queue),
            "rules": {
                "loaded": len(rules.rules) if rules else 0,
                "enabled": sum(1 for rule in rules.rules if rule.ok) if rules else 0,
                "errors": len(rules.errors) if rules else 0,
            },
        }

    def state_frame(self) -> Frame:
        state = self.state()
        return Frame("replay_state", state["cursor_ts"], state)

    # ------------------------------------------------------------- control

    def start(
        self,
        speed_hours_per_second: float | None = None,
        start_ts: datetime | None = None,
        end_ts: datetime | None = None,
        max_gap_s: float | None = None,
        window: tuple | None = None,
    ) -> dict:
        """Run, or resume. A new window restarts the replay inside it.

        `window` sets both ends at once, and a None end means open. It exists
        because a caller who asks to replay from 1 March and says nothing
        about the end means to the end of the data, not to whatever end the
        previous request happened to leave behind.
        """
        with self._lock:
            if speed_hours_per_second is not None:
                self.speed = float(speed_hours_per_second)
            if max_gap_s is not None:
                self.max_gap_s = max_gap_s
            if window is not None:
                start_ts, end_ts = window
                window_changed = start_ts != self._from or end_ts != self._to
                self._from, self._to = start_ts, end_ts
            else:
                window_changed = (start_ts is not None and start_ts != self._from) or (
                    end_ts is not None and end_ts != self._to
                )
                if start_ts is not None:
                    self._from = start_ts
                if end_ts is not None:
                    self._to = end_ts
            # A new window, or a replay that already ran to the end, is a
            # fresh run. A first start is not: events pushed before the
            # judge pressed play are part of this run and must survive it.
            if window_changed or self._finished:
                self._reset_requested = True
            self._running = True
            self._started_once = True
            self._chosen_key = None
        self._wake.set()
        return self.state()

    def pause(self) -> dict:
        with self._lock:
            self._running = False
            self._started_once = True
        self._wake.set()
        return self.state()

    def reset(self) -> dict:
        """Back to the start of the window, paused, with nothing carried over."""
        with self._lock:
            self._running = False
            self._reset_requested = True
            self._started_once = True
            alive = self._alive
        self._wake.set()
        if not alive:
            self._apply_reset()
        return self.state()

    def stop(self) -> dict:
        with self._lock:
            self._stopped = True
            self._running = False
        self._wake.set()
        return self.state()

    def set_speed(self, speed_hours_per_second: float) -> dict:
        with self._lock:
            self.speed = float(speed_hours_per_second)
            # The event being slept towards is now due at a different time.
            self._chosen_key = None
        self._wake.set()
        return self.state()

    def inject(self, events, variant_id=None, synthetic: bool = True) -> int:
        """The red team's entry point. Safe from any thread, at any time."""
        return self.queue.push(events, variant_id=variant_id, synthetic=synthetic)

    @property
    def running(self) -> bool:
        return self._running

    @property
    def started(self) -> bool:
        """Whether anyone has taken control of this replay yet.

        The stream starts a replay nobody has touched, so opening the UI
        shows something rather than a blank screen. Any deliberate action,
        including a pause or a reset, sets this, so a reconnect never undoes
        what somebody meant to do.
        """
        return self._started_once

    @property
    def finished(self) -> bool:
        return self._finished

    # ------------------------------------------------------------ internals

    def _apply_reset(self) -> None:
        with self._lock:
            self._reset_requested = False
            self._source = self._source_factory(self._from, self._to)
            self._pending = None
            # Injected variants belong to the run that was cancelled. The red
            # team pushes again against the fresh replay rather than having
            # last run's events reappear inside this one.
            self.queue.clear()
            self.pipeline.reset()
            self.events_emitted = 0
            self.cursor = self._from
            self._finished = False
            self._last_sim = None
            self._chosen_key = None

    def _peek_base(self):
        if self._source is None:
            self._source = self._source_factory(self._from, self._to)
        if self._pending is None:
            self._pending = next(self._source, None)
        return self._pending

    def _head(self):
        """The next event due, injected or not, as (event, meta, from_queue)."""
        base = self._peek_base()
        injected = self.queue.peek()
        if injected is None and base is None:
            return None
        if base is None:
            return (injected[3], injected[4], True)
        if injected is None:
            return (base, None, False)
        if (injected[0], injected[1]) <= (base.ts, base.line):
            return (injected[3], injected[4], True)
        return (base, None, False)

    def _take(self, from_queue: bool) -> None:
        if from_queue:
            self.queue.pop()
        else:
            self._pending = None

    def _delay_for(self, ts: datetime) -> float:
        if self.fast or self._last_sim is None:
            return 0.0
        gap = (ts - self._last_sim).total_seconds()
        if gap <= 0:
            return 0.0
        delay = gap / (SECONDS_PER_HOUR * max(self.speed, 1e-9))
        if self.max_gap_s:
            delay = min(delay, float(self.max_gap_s))
        return delay

    def _schedule(self, ts: datetime) -> float:
        """When this event is due, measured from the last deadline.

        Anchoring on `self.clock()` instead would make the schedule relative
        to when the previous event actually came out, which folds every
        scheduler overshoot into the next gap and compounds it. The span
        counters on a paced run are what made that visible: the loop was
        asking for 7.0 seconds of sleep across two days of March and taking
        11.9, so a replay advertising six log-hours per second was delivering
        about four.

        Only wall-clock timing changes. The event order, the log timestamps,
        the alerts and the incidents are all unaffected, because none of them
        has ever been a function of when the emitting thread woke up.
        """
        now = self.clock()
        anchor = self._due_at
        if anchor <= 0.0 or anchor < now - MAX_CATCHUP_S:
            anchor = now
        return anchor + self._delay_for(ts)

    def _maybe_reload_rules(self) -> bool:
        if self.rules is None:
            return False
        now = self.clock()
        if now - self._rules_checked_at < RULE_RELOAD_INTERVAL_S:
            return False
        self._rules_checked_at = now
        return self.rules.maybe_reload()

    def _wait(self, seconds: float) -> None:
        self._wake.wait(max(0.0, seconds))
        self._wake.clear()

    def _paced_wait(self, seconds: float) -> None:
        """Wait for pacing, and record what the wait actually cost.

        Counters rather than a span per wait: a paced replay of the March
        window waits tens of thousands of times, and a span each would cost
        more than the sleep it was measuring. The totals land on whatever
        span is already open, so `stream.replay` carries what the scheduler
        did with the delays this engine asked for.
        """
        span = obs.current()
        started = self.clock()
        self._wait(seconds)
        actual = self.clock() - started
        span.add("pace.waits")
        span.add("pace.requested_ms", seconds * 1000.0)
        span.add("pace.actual_ms", actual * 1000.0)
        if actual > seconds:
            span.add("pace.overshoot_ms", (actual - seconds) * 1000.0)

    # ----------------------------------------------------------------- loop

    def frames(self, follow: bool | None = None):
        """Yield frames until the window ends, or forever while following.

        Following is what a live stream wants: when the source runs dry the
        engine stays up, so a variant injected after the last real event
        still arrives and is still detected. The evaluation harness passes
        follow=False and gets a generator that terminates.
        """
        follow = (not self.fast) if follow is None else follow
        with self._lock:
            self._alive = True
        try:
            yield self.state_frame()
            while True:
                if self._stopped:
                    return
                if self._reset_requested:
                    self._apply_reset()
                    yield self.state_frame()
                    continue
                if not self._running:
                    if not follow:
                        return
                    self._wait(IDLE_POLL_S)
                    continue

                self._maybe_reload_rules()
                head = self._head()
                if head is None:
                    if not self._finished:
                        with self._lock:
                            self._finished = True
                        yield self.state_frame()
                    if not follow:
                        return
                    self._wait(IDLE_POLL_S)
                    continue

                event, meta, from_queue = head
                key = (event.ts, event.line, from_queue)
                if self._chosen_key != key:
                    self._chosen_key = key
                    self._due_at = self._schedule(event.ts)
                remaining = self._due_at - self.clock()
                if remaining > MIN_SLEEP_S:
                    self._paced_wait(remaining)
                    continue

                self._take(from_queue)
                self._last_sim = event.ts
                if self.cursor is None or event.ts > self.cursor:
                    self.cursor = event.ts
                self.events_emitted += 1
                self._chosen_key = None

                for frame in self.pipeline.feed(event, meta):
                    yield frame
                if self.events_emitted % STATE_EVERY_EVENTS == 0:
                    yield self.state_frame()
        finally:
            with self._lock:
                self._alive = False

    def run(self, sink=None, follow: bool | None = None) -> None:
        """Drive the loop, handing every frame to the sink. Blocks."""
        target = sink if sink is not None else self.sink
        with obs.span(
            "stream.replay", fast=self.fast, speed_hours_per_second=self.speed
        ) as active:
            frames = 0
            for frame in self.frames(follow=follow):
                frames += 1
                if target is not None:
                    target(frame)
            active.update(frames=frames, events=self.events_emitted)

    def drain(self) -> tuple:
        """Run the whole window as fast as the machine allows.

        The evaluation harness and the tests use this: no pacing, no
        following, alerts and incidents at the end.
        """
        self.fast = True
        with obs.span("stream.replay", fast=True) as active:
            self.start()
            for _frame in self.frames(follow=False):
                pass
            active.set_data("events", self.events_emitted)
        return self.pipeline.alerts, self.pipeline.incidents()
