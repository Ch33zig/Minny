"""Signal and correlator behaviour.

Two halves. The first pins each signal against hand-built events so a failure
names the signal rather than the dataset. The second replays the real file and
asserts the facts the demo rests on: each signal fires on the incident line it
is supposed to, S3 is silent across seven months of baseline, and March
collapses into exactly one incident naming david_m and sarah_j.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from minny import paths
from minny.baselines.model import Baselines
from minny.detect.correlator import Correlator, correlate
from minny.detect.events import DetectEvent
from minny.detect.signals import Detector, RollingState

EASTERN = ZoneInfo("America/New_York")
T0 = datetime(2026, 3, 15, 11, 7, 56, tzinfo=EASTERN)

BASELINE_DOC = {
    "fit_window": {"start": "2025-08-01T08:00:57-04:00", "end": "2026-03-01T00:00:00-05:00"},
    "event_count": 157818,
    "ip_owner": {"10.0.5.12": "sarah_j", "10.0.8.45": "david_m", "10.0.9.99": None},
    "users": {
        "sarah_j": {
            "ips": ["10.0.5.12"],
            "allowed_paths": ["/dashboard", "/finance/reports/q1_draft_CONFIDENTIAL.zip"],
            "denied_paths": ["/hr/directory_full_CONFIDENTIAL.csv"],
            "denied_counts": {"/hr/directory_full_CONFIDENTIAL.csv": 31},
            "templates_seen": [
                "/dashboard",
                "/api/auth/login",
                "/intranet/forum/view/{id}",
                "/intranet/forum/new",
                "/finance/reports/q1_draft_CONFIDENTIAL.zip",
                "/hr/directory_full_CONFIDENTIAL.csv",
            ],
            "hour_hist": {"9": 412},
            "months_observed": 7,
            "auth_fail": {"count": 80, "median_gap_s": 167016.0, "min_gap_s": 809.0, "max_in_30s": 1},
        },
        "david_m": {
            "ips": ["10.0.8.45"],
            "allowed_paths": ["/dashboard", "/intranet/forum/new", "/intranet/forum/view/{id}"],
            "denied_paths": ["/finance/reports/q1_draft_CONFIDENTIAL.zip"],
            "denied_counts": {"/finance/reports/q1_draft_CONFIDENTIAL.zip": 70},
            "templates_seen": ["/dashboard", "/intranet/forum/new", "/intranet/forum/view/{id}"],
            "hour_hist": {"9": 300},
            "months_observed": 7,
            "auth_fail": {"count": 0, "median_gap_s": None, "min_gap_s": None, "max_in_30s": 0},
        },
    },
    "global": {
        "template_freq": {
            "/dashboard": 14530,
            "/api/auth/login": 7819,
            "/intranet/forum/new": 7933,
            "/intranet/forum/view/{id}": 16078,
            "/finance/reports/q1_draft_CONFIDENTIAL.zip": 3238,
            "/hr/directory_full_CONFIDENTIAL.csv": 1624,
        },
        "param_keys": {"/intranet/forum/new": ["topic"], "/api/auth/login": []},
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


@pytest.fixture()
def detector(baselines):
    return Detector(baselines, RollingState())


def event(
    line,
    user="sarah_j",
    ip="10.0.5.12",
    offset=0,
    template="/dashboard",
    status=200,
    method="GET",
    query=None,
    obj_id=None,
    path=None,
):
    return DetectEvent(
        line=line,
        ts=T0 + timedelta(seconds=offset),
        ip=ip,
        user=user,
        method=method,
        path=path or template,
        base=template,
        query=query or {},
        status=status,
        size=0,
        template=template,
        obj_id=obj_id,
    )


def signals_of(alerts):
    return sorted(a["signal"] for a in alerts)


# --- individual signals ------------------------------------------------------


def test_s1_names_the_owner_of_a_foreign_address(detector):
    alerts = detector.feed(event(168343, ip="10.0.8.45", template="/api/auth/login"))
    s1 = [a for a in alerts if a["signal"] == "S1"][0]
    assert s1["severity"] == "high"
    assert s1["ip_owner"] == "david_m"
    assert s1["value"]["known_ips"] == ["10.0.5.12"]
    assert "belongs to david_m" in s1["explanation"]


def test_s1_drops_to_medium_when_the_address_has_no_owner(detector):
    """C's own_ip_takeover operator produces this. Unknown is null, and a
    null owner is a weaker claim rather than an exception."""
    alerts = detector.feed(event(1, ip="10.0.9.99"))
    s1 = [a for a in alerts if a["signal"] == "S1"][0]
    assert s1["severity"] == "medium"
    assert s1["ip_owner"] is None


def test_s1_is_silent_on_the_account_own_address(detector):
    assert detector.feed(event(1)) == []


def test_s2_fires_on_a_success_the_baseline_only_ever_refused(detector):
    alerts = detector.feed(
        event(168338, user="david_m", ip="10.0.8.45",
              template="/finance/reports/q1_draft_CONFIDENTIAL.zip")
    )
    s2 = [a for a in alerts if a["signal"] == "S2"][0]
    assert s2["severity"] == "high"
    assert s2["value"]["baseline_denials"] == 70
    assert s2["value"]["baseline_successes"] == 0


def test_s2_ignores_a_denial(detector):
    alerts = detector.feed(
        event(168315, user="david_m", ip="10.0.8.45", status=403,
              template="/finance/reports/q1_draft_CONFIDENTIAL.zip")
    )
    assert "S2" not in signals_of(alerts)


def test_s3_fires_once_on_the_third_failure(detector):
    fired = []
    for index in range(6):
        alerts = detector.feed(
            event(168321 + index, ip="10.0.8.45", template="/api/auth/login",
                  method="POST", status=401, offset=index * 2)
        )
        fired.extend(a for a in alerts if a["signal"] == "S3")
    assert len(fired) == 1, "a burst is one alert, not one per failure after it"
    assert fired[0]["value"]["failures"] == 3
    assert fired[0]["evidence_lines"] == [168321, 168322, 168323]


def test_s3_is_high_from_a_foreign_host_and_medium_from_the_account_own(detector, baselines):
    for index in range(3):
        alerts = detector.feed(
            event(1 + index, ip="10.0.8.45", template="/api/auth/login",
                  method="POST", status=401, offset=index)
        )
    assert [a for a in alerts if a["signal"] == "S3"][0]["severity"] == "high"

    home = Detector(baselines, RollingState())
    for index in range(3):
        alerts = home.feed(
            event(10 + index, template="/api/auth/login", method="POST",
                  status=401, offset=index)
        )
    assert [a for a in alerts if a["signal"] == "S3"][0]["severity"] == "medium"


def test_s3_does_not_fire_when_the_failures_are_spread_out(detector):
    fired = []
    for index in range(6):
        alerts = detector.feed(
            event(1 + index, ip="10.0.8.45", template="/api/auth/login",
                  method="POST", status=401, offset=index * 31)
        )
        fired.extend(a for a in alerts if a["signal"] == "S3")
    assert fired == [], "walking under the window is what slow_guess is for"


def test_s4_fires_on_a_template_nobody_has_used(detector):
    alerts = detector.feed(
        event(168336, template="/api/admin/role_update", method="POST")
    )
    s4 = [a for a in alerts if a["signal"] == "S4"][0]
    assert s4["severity"] == "high"
    assert s4["value"]["global_baseline_count"] == 0


def test_s4_is_medium_when_other_accounts_have_used_the_template(detector):
    alerts = detector.feed(
        event(1, user="david_m", ip="10.0.8.45",
              template="/hr/directory_full_CONFIDENTIAL.csv", status=403)
    )
    s4 = [a for a in alerts if a["signal"] == "S4"][0]
    assert s4["severity"] == "medium"
    assert s4["value"]["global_baseline_count"] == 1624


def test_s4_works_on_the_normalized_template_not_the_raw_path(detector):
    """A forum view of a post ID nobody has seen is ordinary browsing. Keying
    on `base` here would fire on every new post and bury the stream."""
    alerts = detector.feed(
        event(1, template="/intranet/forum/view/{id}", obj_id=99999,
              path="/intranet/forum/view/99999")
    )
    assert "S4" not in signals_of(alerts)


def test_s5_lists_only_the_parameters_the_baseline_lacks(detector):
    alerts = detector.feed(
        event(168331, user="david_m", ip="10.0.8.45", template="/intranet/forum/new",
              method="POST", status=302,
              query={"topic": "q1_updates", "action": "csrf_role_update"})
    )
    s5 = [a for a in alerts if a["signal"] == "S5"][0]
    assert s5["value"]["unexpected_params"] == ["action"]
    assert s5["value"]["baseline_params"] == ["topic"]


def test_s5_is_silent_on_the_expected_parameter(detector):
    alerts = detector.feed(
        event(1, user="david_m", ip="10.0.8.45", template="/intranet/forum/new",
              method="POST", status=302, query={"topic": "lunch_menu"})
    )
    assert "S5" not in signals_of(alerts)


def test_s6_links_the_post_the_privileged_action_and_the_author(detector):
    """The demo signal. It is the ordering and the gap that are the finding,
    not any one of the three requests."""
    detector.feed(
        event(168332, user="david_m", ip="10.0.8.45", template="/intranet/forum/new",
              method="POST", status=302, offset=-2940,
              query={"topic": "parking_issues", "script": "success"})
    )
    detector.feed(
        event(168333, user="david_m", ip="10.0.8.45",
              template="/intranet/forum/view/{id}", obj_id=1042, offset=-2937)
    )
    detector.feed(event(168335, template="/intranet/forum/view/{id}", obj_id=1042))
    alerts = detector.feed(
        event(168336, template="/api/admin/role_update", method="POST", offset=1)
    )

    s6 = [a for a in alerts if a["signal"] == "S6"][0]
    assert s6["severity"] == "high"
    assert s6["obj_id"] == 1042
    assert s6["value"]["gap_s"] == 1.0
    assert s6["value"]["vector_author"] == "david_m"
    assert s6["evidence_lines"] == [168332, 168333, 168335, 168336]


def test_s6_does_not_fire_outside_the_five_second_window(detector):
    detector.feed(event(168335, template="/intranet/forum/view/{id}", obj_id=1042))
    alerts = detector.feed(
        event(168336, template="/api/admin/role_update", method="POST", offset=30)
    )
    assert "S6" not in signals_of(alerts)


def test_s6_catches_a_renamed_admin_endpoint(detector):
    """The rarity clause is what survives a red-team rename: a POST returning
    200 on a template the baseline has never seen is still privileged."""
    detector.feed(event(1, template="/intranet/forum/view/{id}", obj_id=7))
    alerts = detector.feed(
        event(2, template="/internal/grant_role", method="POST", offset=2)
    )
    assert "S6" in signals_of(alerts)


def test_s7_records_authorship_and_emits_no_alert(detector):
    detector.feed(
        event(168332, user="david_m", ip="10.0.8.45", template="/intranet/forum/new",
              method="POST", status=302, query={"topic": "parking_issues"})
    )
    alerts = detector.feed(
        event(168333, user="david_m", ip="10.0.8.45",
              template="/intranet/forum/view/{id}", obj_id=1042, offset=3)
    )
    assert alerts == []
    record = detector.state.post_author[1042]
    assert (record.user, record.post_line, record.gap_s) == ("david_m", 168332, 3.0)


def test_s7_does_not_claim_a_later_reader_as_the_author(detector):
    detector.feed(
        event(168332, user="david_m", ip="10.0.8.45", template="/intranet/forum/new",
              method="POST", status=302, query={"topic": "parking_issues"})
    )
    detector.feed(
        event(168333, user="david_m", ip="10.0.8.45",
              template="/intranet/forum/view/{id}", obj_id=1042, offset=3)
    )
    detector.feed(event(168335, template="/intranet/forum/view/{id}", obj_id=1042))
    assert detector.state.post_author[1042].user == "david_m"


def test_s8_fires_on_a_status_the_baseline_never_produced(detector):
    alerts = detector.feed(
        event(168330, user="david_m", ip="10.0.8.45", template="/intranet/forum/new",
              method="POST", status=500, query={"topic": "lunch_menu"})
    )
    s8 = [a for a in alerts if a["signal"] == "S8"][0]
    assert s8["severity"] == "high"
    assert s8["value"]["baseline_count"] == 0


def test_s8_ignores_the_statuses_the_application_returns_all_day(detector):
    for status in (200, 302, 401, 403):
        alerts = detector.feed(event(1, status=status))
        assert "S8" not in signals_of(alerts)


def test_no_signal_fires_on_ordinary_off_hours_work(baselines):
    """sarah_j pulls the confidential zip after midnight from her own address
    all through the baseline. The hour histogram is explanation text and must
    never become a threshold, or the demo turns into an argument about her."""
    midnight = Detector(baselines, RollingState())
    at_0019 = datetime(2026, 3, 6, 0, 19, tzinfo=EASTERN)
    alerts = midnight.feed(
        DetectEvent(
            line=161204, ts=at_0019, ip="10.0.5.12", user="sarah_j", method="GET",
            path="/finance/reports/q1_draft_CONFIDENTIAL.zip",
            base="/finance/reports/q1_draft_CONFIDENTIAL.zip", query={}, status=200,
            size=8459200, template="/finance/reports/q1_draft_CONFIDENTIAL.zip",
            obj_id=None,
        )
    )
    assert alerts == []


# --- correlation -------------------------------------------------------------


def _alert(signal, ts, user, ip, ip_owner=None, value=None, lines=None, obj_id=None):
    return {
        "alert_id": f"a_{signal}_{lines[0] if lines else 0}",
        "ts": ts.isoformat(),
        "signal": signal,
        "signal_name": signal,
        "severity": "high",
        "user": user,
        "ip": ip,
        "ip_owner": ip_owner,
        "template": "/x",
        "obj_id": obj_id,
        "value": value or {},
        "evidence_lines": lines or [1],
        "explanation": f"{signal} fired",
        "incident_id": None,
    }


def test_the_owner_edge_joins_two_accounts_into_one_incident():
    incidents = correlate(
        [
            _alert("S1", T0, "sarah_j", "10.0.8.45", ip_owner="david_m", lines=[168343]),
            _alert("S2", T0 + timedelta(hours=1), "david_m", "10.0.8.45", lines=[168338]),
        ]
    )
    assert len(incidents) == 1
    assert incidents[0]["attacker"]["user"] == "david_m"
    assert incidents[0]["victim"]["user"] == "sarah_j"


def test_alerts_beyond_the_window_do_not_merge():
    incidents = correlate(
        [
            _alert("S1", T0, "sarah_j", "10.0.8.45", ip_owner="david_m", lines=[1]),
            _alert("S1", T0 + timedelta(hours=80), "sarah_j", "10.0.8.45",
                   ip_owner="david_m", lines=[2]),
        ]
    )
    assert len(incidents) == 2


def test_a_null_ip_owner_leaves_the_attacker_unnamed_rather_than_guessed():
    incidents = correlate([_alert("S1", T0, "sarah_j", "10.0.9.99", lines=[1])])
    attacker = incidents[0]["attacker"]
    assert attacker["user"] is None
    assert attacker["confidence"] == "low"
    assert attacker["ip"] == "10.0.9.99", "the address is still the lead"
    assert incidents[0]["victim"]["user"] == "sarah_j"


def test_the_content_chain_wins_a_conflict_and_lowers_confidence():
    incidents = correlate(
        [
            _alert("S1", T0, "sarah_j", "10.0.8.45", ip_owner="david_m", lines=[1]),
            _alert(
                "S6", T0 + timedelta(minutes=5), "sarah_j", "10.0.5.12",
                value={"vector_author": "michael_t", "vector_obj_id": 1042,
                       "vector_template": "/intranet/forum/view/{id}"},
                lines=[2], obj_id=1042,
            ),
        ]
    )
    attacker = incidents[0]["attacker"]
    assert attacker["user"] == "michael_t"
    assert attacker["confidence"] == "medium"


def test_an_account_that_escalates_itself_has_no_victim():
    incidents = correlate(
        [
            _alert(
                "S6", T0, "david_m", "10.0.8.45",
                value={"vector_author": "david_m", "vector_obj_id": 7,
                       "vector_template": "/intranet/forum/view/{id}"},
                lines=[1], obj_id=7,
            )
        ]
    )
    assert incidents[0]["attacker"]["user"] == "david_m"
    assert incidents[0]["victim"]["user"] is None


def test_incident_ids_are_stable_across_runs():
    alerts = [_alert("S1", T0, "sarah_j", "10.0.8.45", ip_owner="david_m", lines=[1])]
    first = Correlator().run([dict(a) for a in alerts])[0]["incident_id"]
    second = Correlator().run([dict(a) for a in alerts])[0]["incident_id"]
    assert first == second


def test_an_incident_never_asserts_a_fact_no_alert_carries():
    incidents = correlate(
        [_alert("S1", T0, "sarah_j", "10.0.8.45", ip_owner="david_m", lines=[168343])]
    )
    incident = incidents[0]
    assert incident["asset"] is None, "no S2 alert means no asset to name"
    assert incident["vector"] is None
    assert incident["evidence_emails"] == []
    assert incident["labels"] == {"synthetic": False, "variant_id": None}
    assert all(step["text"] for step in incident["narrative"])


# --- the real dataset --------------------------------------------------------

needs_dataset = pytest.mark.skipif(
    not paths.events_path().exists() or not paths.baselines_path().exists(),
    reason="events.parquet and baselines.json are shared out of band; "
    "set MINNY_DATA_DIR to the main checkout's data directory",
)

INCIDENT_LINE_FOR = {
    "S1": 168343,
    "S2": 168338,
    "S3": 168321,
    "S4": 168336,
    "S5": 168331,
    "S6": 168336,
    "S8": 168330,
}


@pytest.fixture(scope="module")
def replayed():
    import pandas as pd

    from minny.build_events import BASELINE_CUTOFF
    from minny.detect.events import from_frame

    frame = pd.read_parquet(paths.events_path())
    live = Baselines.load()
    cutoff = pd.Timestamp(BASELINE_CUTOFF)

    control = Detector(live).run(from_frame(frame[frame["ts"] < cutoff]))
    detector = Detector(live)
    alerts = detector.run(from_frame(frame[frame["ts"] >= cutoff]))
    incidents = Correlator().run(alerts)
    return {"control": control, "alerts": alerts, "incidents": incidents}


@needs_dataset
def test_the_baseline_window_produces_no_alerts_at_all(replayed):
    """Seven months, 157,818 events, every threshold fitted on them. Anything
    that fires here is a false positive by construction."""
    assert replayed["control"] == []


@needs_dataset
def test_s3_at_three_in_thirty_seconds_has_zero_baseline_hits(replayed):
    assert [a for a in replayed["control"] if a["signal"] == "S3"] == []


@needs_dataset
@pytest.mark.parametrize(("signal", "line"), sorted(INCIDENT_LINE_FOR.items()))
def test_each_signal_fires_on_its_incident_line(replayed, signal, line):
    hits = [
        a
        for a in replayed["alerts"]
        if a["signal"] == signal and line in a["evidence_lines"]
    ]
    assert hits, f"{signal} did not fire on line {line}"


@needs_dataset
def test_s7_attributes_post_1042_to_david_m(replayed):
    s6 = [a for a in replayed["alerts"] if a["signal"] == "S6"]
    assert len(s6) == 1
    assert s6[0]["value"]["vector_obj_id"] == 1042
    assert s6[0]["value"]["vector_author"] == "david_m"


@needs_dataset
def test_march_produces_exactly_one_incident_naming_both_roles(replayed):
    incidents = replayed["incidents"]
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["attacker"]["user"] == "david_m"
    assert incident["victim"]["user"] == "sarah_j"
    assert incident["attacker"]["confidence"] == "high"
    assert incident["asset"] == "/finance/reports/q1_draft_CONFIDENTIAL.zip"
    assert incident["vector"] == {
        "template": "/intranet/forum/view/{id}",
        "obj_id": 1042,
    }


@needs_dataset
def test_no_march_alert_falls_outside_the_incident(replayed):
    """The false-positive number the whole watchdog is judged on."""
    claimed = {aid for inc in replayed["incidents"] for aid in inc["alerts"]}
    loose = [a for a in replayed["alerts"] if a["alert_id"] not in claimed]
    assert loose == []


@needs_dataset
def test_every_alert_line_is_a_known_incident_line(replayed):
    """From GROUND-TRUTH.md. An alert on any other line is a false positive
    even though it landed inside the incident."""
    known = set(range(168311, 168315)) | set(range(168321, 168327)) | {
        168330, 168331, 168332, 168333, 168335, 168336, 168337, 168338,
        168339, 168340,
    } | set(range(168343, 168347))
    touched = {n for a in replayed["alerts"] for n in a["evidence_lines"]}
    assert touched <= known, f"alerts on non-incident lines: {sorted(touched - known)}"
