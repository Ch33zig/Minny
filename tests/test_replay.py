"""Replay engine, injection queue and stream framing.

Three things are pinned here because three other people depend on them.

The injection queue must merge by timestamp, including when it is pushed
from another thread in the middle of a running replay. That is the judge
panel's whole mechanism: the red team pushes variant events in and the
detector must see them in time order, indistinguishable from real traffic.

Incidents must be re-emitted every time they change, under the same
`incident_id` and with a rising `alert_count`. The front end upserts on that
key and animates on that number, so one frame at the end would render a case
file and show none of it being built.

And the streaming path must agree with the batch path exactly. They share a
Pipeline precisely so they cannot disagree, and the last test in this file is
what proves the sharing is real.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from minny import paths
from minny.baselines.model import Baselines
from minny.detect.correlator import Correlator
from minny.detect.events import DetectEvent
from minny.detect.replay import (
    MAX_CATCHUP_S,
    Frame,
    InjectionQueue,
    Pipeline,
    ReplayEngine,
    event_payload,
)
from minny.detect.signals import Detector

LOG_TZ = timezone(timedelta(hours=-4))

BASELINE_DOC = {
    "fit_window": {
        "start": "2025-08-01T08:00:57-04:00",
        "end": "2026-03-01T00:00:00-04:00",
    },
    "event_count": 157818,
    "ip_owner": {"10.0.5.12": "sarah_j", "10.0.8.45": "david_m"},
    "users": {
        "sarah_j": {
            "ips": ["10.0.5.12"],
            "allowed_paths": ["/dashboard", "/api/auth/login"],
            "denied_paths": [],
            "denied_counts": {},
            "templates_seen": ["/dashboard", "/api/auth/login"],
            "hour_hist": {"9": 412},
            "months_observed": 7,
            "auth_fail": {"count": 14, "max_in_30s": 1},
        },
        "david_m": {
            "ips": ["10.0.8.45"],
            "allowed_paths": ["/dashboard"],
            "denied_paths": [],
            "denied_counts": {},
            "templates_seen": ["/dashboard"],
            "hour_hist": {"9": 300},
            "months_observed": 7,
            "auth_fail": {"count": 0, "max_in_30s": 0},
        },
    },
    "global": {
        "template_freq": {"/dashboard": 14530, "/api/auth/login": 7819},
        "param_keys": {"/api/auth/login": []},
        "privileged_templates": [],
        "privileged_rule": {"prefixes": ["/api/admin/"], "rare_post_success_k": 100},
        "auth_fail_window_s": 30,
        "status_freq": {"200": 122229, "302": 30154, "401": 782, "403": 4653},
        "rare_status_n": 10,
    },
}


@pytest.fixture()
def baselines():
    return Baselines.from_document(BASELINE_DOC)


def event(
    line: int,
    minute: int,
    second: int = 0,
    user: str = "sarah_j",
    ip: str = "10.0.5.12",
    path: str = "/dashboard",
    status: int = 200,
    method: str = "GET",
) -> DetectEvent:
    return DetectEvent(
        line=line,
        ts=datetime(2026, 3, 15, 10, minute, second, tzinfo=LOG_TZ),
        ip=ip,
        user=user,
        method=method,
        path=path,
        base=path,
        query={},
        status=status,
        size=2048,
        template=path,
        obj_id=None,
        raw=f"{ip} - {user} [15/Mar/2026] \"{method} {path}\" {status} 2048",
    )


def quiet(count: int = 5) -> list:
    """Ordinary traffic the baseline explains, so nothing fires on it."""
    return [event(line=index, minute=index * 2) for index in range(1, count + 1)]


def lines_of(frames: list, kind: str = "event") -> list:
    return [frame.data["line"] for frame in frames if frame.type == kind]


def wait_until(condition, timeout: float = 5.0) -> None:
    """Wait for the replay thread to get somewhere, and fail rather than hang."""
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "the replay thread did not get there"
        time.sleep(0.005)


# ------------------------------------------------------- the injection queue


def test_the_queue_orders_by_timestamp_not_by_arrival():
    queue = InjectionQueue()
    queue.push([event(300, 30), event(100, 10)])
    queue.push([event(200, 20)])
    assert [queue.pop()[3].line for _ in range(3)] == [100, 200, 300]


def test_the_queue_carries_the_variant_label_with_every_event():
    queue = InjectionQueue()
    queue.push([event(100, 10)], variant_id="v42")
    _ts, _line, _seq, injected, meta = queue.pop()
    assert injected.line == 100
    assert meta == {"synthetic": True, "variant_id": "v42"}


def test_the_queue_survives_several_threads_pushing_at_once():
    """C generates on a worker thread. Ordering is not allowed to depend on it."""
    queue = InjectionQueue()
    pushers = [
        threading.Thread(
            target=queue.push,
            args=([event(line=base + offset, minute=base + offset) for offset in range(5)],),
        )
        for base in (0, 10, 20, 30)
    ]
    for thread in pushers:
        thread.start()
    for thread in pushers:
        thread.join()

    drained = []
    while len(queue):
        drained.append(queue.pop()[3])
    assert len(drained) == 20
    assert drained == sorted(drained, key=lambda item: (item.ts, item.line))


def test_injected_events_merge_into_the_source_by_timestamp(baselines):
    engine = ReplayEngine.from_events(quiet(5), baselines, fast=True)
    engine.inject([event(900, 3), event(901, 7)], variant_id="v1")
    engine.start()
    frames = list(engine.frames(follow=False))

    # Source events sit at minutes 2, 4, 6, 8, 10 and the injected pair at 3
    # and 7, so a merge by timestamp interleaves them exactly here.
    assert lines_of(frames) == [1, 900, 2, 3, 901, 4, 5]


def test_an_event_pushed_mid_replay_lands_in_time_order(baselines):
    """The push happens while the loop is asleep between two real events."""
    engine = ReplayEngine.from_events(
        quiet(5), baselines, speed_hours_per_second=0.5, max_gap_s=0.05
    )
    engine.start()
    seen: list = []

    def drive():
        for frame in engine.frames(follow=True):
            seen.append(frame)
            if frame.type == "event" and frame.data["line"] == 5:
                engine.stop()

    driver = threading.Thread(target=drive)
    driver.start()
    wait_until(lambda: any(frame.type == "event" for frame in seen))
    engine.inject([event(950, 9)], variant_id="v7")
    driver.join(timeout=10)
    assert not driver.is_alive()

    emitted = lines_of(seen)
    assert 950 in emitted
    assert emitted.index(950) == emitted.index(4) + 1
    assert emitted == sorted(
        emitted, key=lambda line: (9 if line == 950 else [0, 2, 4, 6, 8, 10][line])
    )


def test_an_injected_event_is_labelled_everywhere_it_shows_up(baselines):
    """An alert raised by an injected event is synthetic, and so is its incident."""
    engine = ReplayEngine.from_events(quiet(2), baselines, fast=True)
    engine.inject(
        [event(960, 5, user="sarah_j", ip="10.0.8.45", path="/api/auth/login")],
        variant_id="v42",
    )
    engine.start()
    frames = list(engine.frames(follow=False))

    injected = [f for f in frames if f.type == "event" and f.data["line"] == 960]
    assert injected[0].data["synthetic"] is True
    assert injected[0].data["variant_id"] == "v42"

    alerts = [f.data for f in frames if f.type == "alert"]
    assert alerts and all(alert["variant_id"] == "v42" for alert in alerts)
    incidents = [f.data for f in frames if f.type == "incident"]
    assert incidents[-1]["labels"] == {"synthetic": True, "variant_id": "v42"}


def test_reset_drops_the_queue_and_returns_to_the_window_start(baselines):
    engine = ReplayEngine.from_events(quiet(5), baselines, fast=True)
    engine.inject([event(900, 3)])
    engine.start()
    list(engine.frames(follow=False))
    assert engine.state()["events_emitted"] == 6

    engine.reset()
    state = engine.state()
    assert state["events_emitted"] == 0
    assert state["running"] is False
    assert state["injected_pending"] == 0
    assert state["alerts_emitted"] == 0

    engine.start()
    assert lines_of(list(engine.frames(follow=False))) == [1, 2, 3, 4, 5]


# ------------------------------------------------------------ incident frames


def chain(ip: str = "10.0.8.45") -> list:
    """Four failed logins from a host the account has never used.

    Enough to raise S1 on every one of them and S3 on the third, which is a
    case that grows over four events rather than appearing complete.
    """
    return [
        event(index, 10, second=index * 4, user="sarah_j", ip=ip,
              path="/api/auth/login", status=401, method="POST")
        for index in range(1, 5)
    ]


def test_an_incident_is_re_emitted_every_time_it_changes(baselines):
    engine = ReplayEngine.from_events(chain(), baselines, fast=True)
    engine.start()
    frames = list(engine.frames(follow=False))
    incidents = [f.data for f in frames if f.type == "incident"]

    assert len(incidents) > 1
    assert len({incident["incident_id"] for incident in incidents}) == 1
    counts = [incident["alert_count"] for incident in incidents]
    assert counts == sorted(counts)
    assert counts[0] < counts[-1]
    assert counts[-1] == len(incidents[-1]["alerts"])


def test_the_frames_for_one_event_arrive_event_then_alert_then_incident(baselines):
    pipeline = Pipeline(baselines)
    frames = pipeline.feed(chain()[0])
    assert [frame.type for frame in frames] == ["event", "alert", "incident"]


def test_a_merge_tells_the_ui_where_the_absorbed_incident_went(baselines):
    """Two stories that a later alert joins must not leave a stale card."""
    pipeline = Pipeline(baselines)
    # Two separate clusters first: different accounts, different addresses.
    pipeline.feed(event(1, 1, user="sarah_j", ip="10.0.9.99", path="/api/auth/login",
                        status=401, method="POST"))
    pipeline.feed(event(2, 2, user="david_m", ip="10.0.7.77", path="/api/auth/login",
                        status=401, method="POST"))
    assert len(pipeline.correlator.clusters) == 2
    first, second = (cluster.incident_id for cluster in pipeline.correlator.clusters)

    # An alert on david_m from sarah_j's address bridges the two.
    frames = pipeline.feed(
        event(3, 3, user="david_m", ip="10.0.9.99", path="/api/auth/login",
              status=401, method="POST")
    )
    merged = [
        frame.data
        for frame in frames
        if frame.type == "incident" and frame.data.get("status") == "merged"
    ]
    assert len(pipeline.correlator.clusters) == 1
    assert [entry["incident_id"] for entry in merged] == [second]
    assert merged[0]["merged_into"] == first


# -------------------------------------------------------------- replay state


def test_state_reports_what_the_contract_says_it_reports(baselines):
    engine = ReplayEngine.from_events(quiet(3), baselines, fast=True)
    state = engine.state()
    for key in ("running", "speed_hours_per_second", "cursor_ts", "events_emitted"):
        assert key in state
    assert state["running"] is False

    engine.start(speed_hours_per_second=12.0)
    list(engine.frames(follow=False))
    state = engine.state()
    assert state["running"] is True
    assert state["speed_hours_per_second"] == 12.0
    assert state["events_emitted"] == 3
    assert state["cursor_ts"] == "2026-03-15T10:06:00-04:00"
    assert state["finished"] is True


def test_pause_stops_the_cursor_and_start_resumes_it(baselines):
    engine = ReplayEngine.from_events(quiet(6), baselines,
                                      speed_hours_per_second=0.2, max_gap_s=0.05)
    engine.start()
    seen: list = []

    def drive():
        for frame in engine.frames(follow=True):
            seen.append(frame)

    driver = threading.Thread(target=drive, daemon=True)
    driver.start()
    wait_until(lambda: len(lines_of(seen)) >= 2)
    engine.pause()
    paused_at = engine.state()["events_emitted"]
    assert engine.state()["running"] is False

    engine.start()
    wait_until(lambda: engine.state()["events_emitted"] > paused_at)
    assert engine.state()["events_emitted"] > paused_at
    engine.stop()
    driver.join(timeout=5)


def test_speed_is_simulated_hours_per_wall_clock_second(baselines):
    engine = ReplayEngine.from_events(quiet(2), baselines, speed_hours_per_second=6.0)
    engine._last_sim = datetime(2026, 3, 15, 10, 0, tzinfo=LOG_TZ)
    # One simulated hour at six hours per second is a sixth of a second.
    assert engine._delay_for(datetime(2026, 3, 15, 11, 0, tzinfo=LOG_TZ)) == pytest.approx(
        1 / 6
    )
    engine.set_speed(1.0)
    assert engine._delay_for(datetime(2026, 3, 15, 11, 0, tzinfo=LOG_TZ)) == pytest.approx(
        1.0
    )
    # The clamp keeps a quiet stretch of log from being a quiet stretch of demo.
    engine.max_gap_s = 0.25
    assert engine._delay_for(datetime(2026, 3, 16, 10, 0, tzinfo=LOG_TZ)) == 0.25


def test_pacing_absorbs_an_overrun_instead_of_compounding_it(baselines):
    """Each deadline comes from the last deadline, not from the clock.

    Anchoring on the clock makes every event's gap start when the previous
    event actually came out, so a scheduler that overshoots by ten
    milliseconds adds ten milliseconds to the replay, every event, forever.
    Measured over two days of March at the default speed that was a 62%
    overrun: 7.0 seconds of requested sleep taking 11.9, because this
    platform's timer rounds every wait between 2 and 15 ms up to a full
    16 ms tick and 481 waits carried the error forward.
    """
    now = {"t": 100.0}
    engine = ReplayEngine.from_events(
        quiet(2), baselines, speed_hours_per_second=6.0, clock=lambda: now["t"]
    )
    base = datetime(2026, 3, 15, 10, 0, tzinfo=LOG_TZ)
    engine._last_sim = base

    # One simulated hour at six hours per second is a sixth of a second.
    first = engine._schedule(base + timedelta(hours=1))
    assert first == pytest.approx(100.0 + 1 / 6)

    engine._due_at = first
    engine._last_sim = base + timedelta(hours=1)
    # The wait overran its deadline by ten milliseconds.
    now["t"] = first + 0.010
    second = engine._schedule(base + timedelta(hours=2))
    assert second == pytest.approx(first + 1 / 6)
    # Anchoring on the clock would have put it ten milliseconds later, and
    # the next event ten milliseconds after that.
    assert second < now["t"] + 1 / 6

    # A pause longer than the catch-up clamp restarts the schedule from now
    # rather than sprinting through a backlog on resume.
    engine._due_at = second
    engine._last_sim = base + timedelta(hours=2)
    now["t"] = second + MAX_CATCHUP_S + 5.0
    third = engine._schedule(base + timedelta(hours=3))
    assert third == pytest.approx(now["t"] + 1 / 6)


def test_fast_mode_does_not_sleep(baselines):
    engine = ReplayEngine.from_events(quiet(3), baselines, fast=True)
    engine._last_sim = datetime(2026, 3, 15, 10, 0, tzinfo=LOG_TZ)
    assert engine._delay_for(datetime(2026, 3, 20, 10, 0, tzinfo=LOG_TZ)) == 0.0


# ------------------------------------------------------------- the envelope


def test_the_frame_envelope_is_the_contract_shape(baselines):
    envelope = Frame("alert", "2026-03-15T10:00:00-04:00", {"alert_id": "a_1"}).envelope(7)
    assert envelope == {
        "type": "alert",
        "seq": 7,
        "ts": "2026-03-15T10:00:00-04:00",
        "data": {"alert_id": "a_1"},
    }
    # One JSON object on one line, which is what an SSE data: field carries.
    assert "\n" not in json.dumps(envelope)


def test_the_event_payload_is_the_evidence_shape():
    payload = event_payload(event(11, 4), {"synthetic": True, "variant_id": "v1"})
    assert set(payload) == {
        "line", "raw", "ts", "user", "ip", "method", "path", "status", "size",
        "synthetic", "variant_id",
    }


def test_sequence_numbers_are_monotonic_across_threads():
    """Every client sees one numbering, so a hole in it is a dropped frame."""
    from minny.api.routes_detect import StreamHub

    hub = StreamHub()
    seqs: list = []
    lock = threading.Lock()

    def publish_many():
        local = [hub.publish(Frame("event", None, {}))["seq"] for _ in range(200)]
        with lock:
            seqs.extend(local)

    threads = [threading.Thread(target=publish_many) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(seqs) == list(range(1, 801))
    assert len(set(seqs)) == 800


def test_a_late_subscriber_is_backfilled_with_the_original_numbers():
    from minny.api.routes_detect import StreamHub

    hub = StreamHub()
    for index in range(10):
        hub.publish(Frame("event", None, {"line": index}))
    recent = hub._recent(4)
    assert [envelope["seq"] for envelope in recent] == [7, 8, 9, 10]


# ---------------------------------------------------------- the real dataset

needs_dataset = pytest.mark.skipif(
    not paths.events_path().exists() or not paths.baselines_path().exists(),
    reason="events.parquet and baselines.json are shared out of band; "
    "set MINNY_DATA_DIR to the main checkout's data directory",
)


@pytest.fixture(scope="module")
def dataset():
    import pandas as pd

    from minny.build_events import BASELINE_CUTOFF
    from minny.detect.events import from_frame

    frame = pd.read_parquet(paths.events_path())
    live = Baselines.load()

    def factory(start, end):
        selected = frame
        if start is not None:
            selected = selected[selected["ts"] >= pd.Timestamp(start)]
        if end is not None:
            selected = selected[selected["ts"] < pd.Timestamp(end)]
        return from_frame(selected)

    march = frame[frame["ts"] >= pd.Timestamp(BASELINE_CUTOFF)]
    batch_alerts = Detector(live).run(from_frame(march))
    batch_incidents = Correlator().run(batch_alerts)

    engine = ReplayEngine(factory, live, fast=True, start_ts=BASELINE_CUTOFF)
    stream_alerts, stream_incidents = engine.drain()

    return {
        "factory": factory,
        "baselines": live,
        "cutoff": BASELINE_CUTOFF,
        "batch_alerts": batch_alerts,
        "batch_incidents": batch_incidents,
        "stream_alerts": stream_alerts,
        "stream_incidents": stream_incidents,
        "engine": engine,
    }


@needs_dataset
def test_streaming_march_reproduces_the_batch_result_exactly(dataset):
    """The two paths share a Pipeline. This is what says the sharing is real.

    Alerts are compared by id rather than by position: several signals can
    fire on one event, and the stream emits those in the order the correlator
    sorts them while the batch loop emits them in signal order. Same alerts,
    same clusters, same incident ids, and the ids are derived from the
    evidence, so an equal set of ids is an equal set of findings.
    """
    assert sorted(alert["alert_id"] for alert in dataset["stream_alerts"]) == sorted(
        alert["alert_id"] for alert in dataset["batch_alerts"]
    )
    assert [incident["incident_id"] for incident in dataset["stream_incidents"]] == [
        incident["incident_id"] for incident in dataset["batch_incidents"]
    ]
    streamed = {alert["alert_id"]: alert for alert in dataset["stream_alerts"]}
    for alert in dataset["batch_alerts"]:
        assert streamed[alert["alert_id"]] == alert


@needs_dataset
def test_the_replayed_march_window_is_one_incident_naming_both_roles(dataset):
    incidents = dataset["stream_incidents"]
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["attacker"]["user"] == "david_m"
    assert incident["victim"]["user"] == "sarah_j"
    assert incident["asset"] == "/finance/reports/q1_draft_CONFIDENTIAL.zip"


@needs_dataset
def test_the_replayed_march_window_has_no_alert_outside_the_incident(dataset):
    """The false-positive number the whole watchdog is judged on, streamed."""
    claimed = {
        alert_id
        for incident in dataset["stream_incidents"]
        for alert_id in incident["alerts"]
    }
    loose = [a for a in dataset["stream_alerts"] if a["alert_id"] not in claimed]
    assert loose == []


@needs_dataset
def test_the_baseline_window_still_produces_no_alerts_through_the_engine(dataset):
    engine = ReplayEngine(
        dataset["factory"], dataset["baselines"], fast=True, end_ts=dataset["cutoff"]
    )
    alerts, incidents = engine.drain()
    assert alerts == []
    assert incidents == []
    assert engine.state()["events_emitted"] == 157818
