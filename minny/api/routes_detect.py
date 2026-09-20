"""Detector routes (track B), mounted under /api by minny.api.app.

Routes are declared without the /api prefix because the application adds it.
Declaring it here too would serve them at /api/api and nobody would notice
until the UI was already wired up.

The artifact routes serve files on disk written by
`python -m minny.detect.run`, re-read when their mtime changes. That means a
replay in one terminal is visible to the API in another without a restart,
which is the difference between iterating on signals and restarting the demo.

The live routes are different animals. One `ReplayEngine` runs on a
background thread for the whole process, every client shares it, and
`StreamHub` fans its frames out over SSE with a single monotonic sequence
number so a gap in the numbers means a dropped frame rather than two clients
seeing two different replays. `/rules` is additive to the contract's route
table: it reports what the detector actually loaded from
detection-rules/rules.yaml, including anything that failed to parse, which is
the detector's own view rather than C's proposal-and-gate view at
`/blue/proposals`.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections import deque
from datetime import datetime
from pathlib import Path

import pandas as pd
from fastapi import APIRouter, Body, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from minny import paths
from minny.baselines.model import Baselines
from minny.build_events import BASELINE_CUTOFF
from minny.detect.events import DetectEvent, from_frame, from_mapping
from minny.detect.replay import Frame, ReplayEngine
from minny.detect.rules import RuleSet

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
        info = path.stat()
        # Size as well as mtime: two writes inside one filesystem clock tick
        # are rare but a stale replay served to the UI is not worth the risk.
        stamp = (info.st_mtime_ns, info.st_size)
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


def _opened(incident: dict) -> datetime:
    try:
        return datetime.fromisoformat(incident["opened_ts"])
    except (KeyError, TypeError, ValueError):
        return datetime.min.replace(tzinfo=None)


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
    # Parsed rather than compared as text. The dataset spans a DST change, so
    # two incidents on the same wall-clock date can carry different offsets and
    # string order would put them the wrong way round.
    return sorted(incidents, key=_opened, reverse=True)


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


# --------------------------------------------------------------- the stream

# Proxies close an idle connection long before this, so the interval is the
# contract's 15 seconds rather than anything tuned.
HEARTBEAT_S = 15

# Frames kept for a client that connects late or reconnects after a drop.
# Sequence numbers are global, so a reconnecting client recognises what it
# has already seen and a gap in the numbers is a real gap.
RING_SIZE = 500
BACKFILL_DEFAULT = 50

# One replay, shared by every client. This is a demo, not a tenant per judge.
DEFAULT_SPEED_HOURS_PER_SECOND = 6.0

# A quiet stretch of March should not be a quiet stretch of demo. The cursor
# still crosses the whole gap; it just does not take the whole gap to do it.
DEFAULT_MAX_GAP_S = 2.0


class StreamHub:
    """Fans replay frames out to every connected client.

    The replay runs on its own thread and the stream is served on the event
    loop, so `publish` is thread-safe and hands the frame over with
    `call_soon_threadsafe`. Sequence numbers are assigned here, once, under a
    lock: every client sees the same `seq` for the same frame, which is what
    makes a missing number mean a dropped frame rather than a different view
    of the replay.
    """

    def __init__(self, ts_provider=None):
        self._lock = threading.Lock()
        self._seq = 0
        self._ring: deque = deque(maxlen=RING_SIZE)
        self._subscribers: set = set()
        self._loop = None
        self._heartbeat = None
        self._ts_provider = ts_provider

    @property
    def seq(self) -> int:
        return self._seq

    def publish(self, frame) -> dict:
        with self._lock:
            self._seq += 1
            envelope = frame.envelope(self._seq)
            self._ring.append(envelope)
            loop = self._loop
        if loop is not None:
            try:
                loop.call_soon_threadsafe(self._fanout, envelope)
            except RuntimeError:
                # The loop is shutting down. The frame is still in the ring,
                # so a client that reconnects will pick it up.
                pass
        return envelope

    def _fanout(self, envelope: dict) -> None:
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(envelope)
            except asyncio.QueueFull:
                # A client too slow to keep up loses the oldest frame it has
                # not read. It sees the hole in `seq` and can reconnect; the
                # alternative is the replay thread blocking on one browser.
                try:
                    queue.get_nowait()
                    queue.put_nowait(envelope)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

    def _recent(self, count: int) -> list:
        with self._lock:
            frames = list(self._ring)
        return frames[-count:] if count > 0 else []

    def heartbeat_ts(self):
        if self._ts_provider is not None:
            stamp = self._ts_provider()
            if stamp:
                return stamp
        return datetime.now().astimezone().isoformat()

    async def _beat(self) -> None:
        while self._subscribers:
            await asyncio.sleep(HEARTBEAT_S)
            if not self._subscribers:
                break
            self.publish(Frame("heartbeat", self.heartbeat_ts(), {}))

    def _ensure_heartbeat(self) -> None:
        if self._heartbeat is None or self._heartbeat.done():
            self._heartbeat = asyncio.ensure_future(self._beat())

    async def subscribe(self, backfill: int = BACKFILL_DEFAULT):
        loop = asyncio.get_running_loop()
        with self._lock:
            self._loop = loop
        queue: asyncio.Queue = asyncio.Queue(maxsize=2000)
        self._subscribers.add(queue)
        self._ensure_heartbeat()
        try:
            last = 0
            for envelope in self._recent(backfill):
                last = envelope["seq"]
                yield envelope
            while True:
                envelope = await queue.get()
                if envelope["seq"] <= last:
                    # Already delivered in the backfill. Skipping it keeps
                    # `seq` strictly increasing within one connection.
                    continue
                last = envelope["seq"]
                yield envelope
        finally:
            self._subscribers.discard(queue)


class ReplayService:
    """Owns the one replay engine and the thread that drives it."""

    def __init__(self):
        self._lock = threading.Lock()
        self._engine = None
        self._thread = None
        self._events = None
        self._rules = None
        self.hub = StreamHub(ts_provider=self._cursor_ts)

    def _cursor_ts(self):
        engine = self._engine
        return engine.state()["cursor_ts"] if engine else None

    def _frame(self):
        if self._events is None:
            path = paths.require(paths.events_path())
            self._events = pd.read_parquet(path)
        return self._events

    def rules(self):
        """The live ruleset, shared with the engine so a reload reaches both."""
        if self._rules is None:
            self._rules = RuleSet.load()
        return self._rules

    def _source_factory(self):
        def factory(start, end):
            selected = self._frame()
            if start is not None:
                selected = selected[selected["ts"] >= pd.Timestamp(start)]
            if end is not None:
                selected = selected[selected["ts"] < pd.Timestamp(end)]
            return from_frame(selected)

        return factory

    def engine(self):
        """The replay, built on first use. Raises if the parquet is missing."""
        with self._lock:
            if self._engine is None:
                self._frame()  # fail before a thread exists, not after
                self._engine = ReplayEngine(
                    self._source_factory(),
                    Baselines.load(),
                    rules=self.rules(),
                    speed_hours_per_second=DEFAULT_SPEED_HOURS_PER_SECOND,
                    max_gap_s=DEFAULT_MAX_GAP_S,
                    start_ts=BASELINE_CUTOFF,
                )
            engine = self._engine
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(
                    target=engine.run,
                    kwargs={"sink": self.hub.publish, "follow": True},
                    name="minny-replay",
                    daemon=True,
                )
                self._thread.start()
            return engine

    def autostart(self):
        """Start a replay nobody has started yet, and leave a paused one alone."""
        engine = self.engine()
        if not engine.started:
            engine.start()
        return engine

    def control(self, action: str, speed=None, window=None, max_gap_s=None):
        engine = self.engine()
        if action == "start":
            state = engine.start(
                speed_hours_per_second=speed, window=window, max_gap_s=max_gap_s
            )
        elif action == "pause":
            if speed is not None:
                engine.set_speed(speed)
            state = engine.pause()
        elif action == "reset":
            if speed is not None:
                engine.set_speed(speed)
            if window is not None:
                # Move the window first, then reset into it, so a reset with
                # a window is one action rather than two visible states.
                engine.start(window=window)
                engine.pause()
            state = engine.reset()
        else:
            raise ValueError(action)
        # Published as well as returned: the client that pressed the button
        # gets it in the response, everyone else gets it on the stream.
        self.hub.publish(engine.state_frame())
        return state

    def inject(self, events, variant_id=None, synthetic: bool = True) -> dict:
        engine = self.engine()
        accepted = engine.inject(
            events, variant_id=variant_id, synthetic=synthetic
        )
        self.hub.publish(engine.state_frame())
        return {"accepted": accepted, "replay": engine.state()}


SERVICE = ReplayService()


def inject_events(events, variant_id=None, synthetic: bool = True) -> dict:
    """Push events into the running replay. Track C's entry point.

    Call it from any thread, at any point in a replay, with `DetectEvent`
    objects or with plain mappings. The events merge into the stream by
    timestamp, so the detector sees them exactly as it sees real traffic, and
    every alert they raise is labelled with the variant that produced it.

        from minny.api.routes_detect import inject_events
        inject_events(rendered_lines, variant_id="v42")
    """
    prepared = [
        event if isinstance(event, DetectEvent) else from_mapping(event)
        for event in events
    ]
    return SERVICE.inject(prepared, variant_id=variant_id, synthetic=synthetic)


def _parse_ts(value, field_name: str):
    if value in (None, ""):
        return None
    try:
        stamp = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise ValueError(f"{field_name} is not an ISO 8601 timestamp: {exc}") from exc
    if stamp.tzinfo is None:
        # The dataset carries a fixed offset on every line. Reading a naive
        # timestamp as that offset keeps a window the caller typed by hand
        # meaning what the log means.
        stamp = stamp.replace(tzinfo=BASELINE_CUTOFF.tzinfo)
    return stamp


@router.post("/replay/control")
async def replay_control(payload: dict = Body(default=None)):
    """Start, pause or reset the shared replay. Returns the new state."""
    body = payload or {}
    action = str(body.get("action", "")).lower()
    if action not in ("start", "pause", "reset"):
        return _error(
            400,
            "bad_request",
            "action must be one of start, pause, reset",
        )

    speed = body.get("speed_hours_per_second")
    if speed is not None:
        try:
            speed = float(speed)
        except (TypeError, ValueError):
            return _error(400, "bad_request", "speed_hours_per_second must be a number")
        if speed <= 0:
            return _error(400, "bad_request", "speed_hours_per_second must be positive")

    try:
        start_ts = _parse_ts(body.get("from"), "from")
        end_ts = _parse_ts(body.get("to"), "to")
    except ValueError as exc:
        return _error(400, "bad_request", str(exc))

    max_gap_s = body.get("max_gap_s")
    if max_gap_s is not None:
        try:
            max_gap_s = float(max_gap_s)
        except (TypeError, ValueError):
            return _error(400, "bad_request", "max_gap_s must be a number")

    # A request that mentions either end of the window sets both, so asking
    # to replay from 1 March with no end means to the end of the data rather
    # than to whatever end the last request left behind.
    window = (start_ts, end_ts) if ("from" in body or "to" in body) else None

    try:
        return SERVICE.control(
            action, speed=speed, window=window, max_gap_s=max_gap_s
        )
    except FileNotFoundError:
        return _missing(paths.events_path(), "python -m minny.build_events")


@router.get("/stream")
async def stream(request: Request, backfill: int = BACKFILL_DEFAULT):
    """The live monitor, as Server-Sent Events.

    One JSON object per `data:` line, typed `event`, `alert`, `incident`,
    `replay_state` or `heartbeat`, with a monotonic `seq`. Opening the stream
    starts a replay that has never been started, so the UI shows the case
    building itself without anyone having to press anything first; a replay
    a judge paused stays paused.

    `backfill` replays the last N frames from the hub's ring so a client that
    connects late, or reconnects after a drop, sees recent context instead of
    an empty screen. Those frames keep their original sequence numbers.
    """
    try:
        SERVICE.autostart()
    except FileNotFoundError:
        return _missing(paths.events_path(), "python -m minny.build_events")

    count = max(0, min(int(backfill), RING_SIZE))

    async def frames():
        async for envelope in SERVICE.hub.subscribe(count):
            yield {"data": json.dumps(envelope, separators=(",", ":"))}

    return EventSourceResponse(frames())


@router.get("/replay/state")
def replay_state():
    """The same payload the `replay_state` frame carries, for a cold client."""
    try:
        return SERVICE.engine().state()
    except FileNotFoundError:
        return _missing(paths.events_path(), "python -m minny.build_events")


@router.get("/rules")
def get_rules():
    """Loaded rules and their parse errors.

    Additive to the contract's route table and owned by this router. The
    blue agent's proposals and their gate results are C's `/blue/proposals`;
    this is the detector's own view of what it actually loaded, which is what
    the UI needs to show a rule that did not parse.
    """
    ruleset = SERVICE.rules()
    ruleset.maybe_reload()
    return ruleset.describe()
