"""Guards on the baseline fit.

The two facts these tests pin are the ones that would silently destroy every
downstream number: a March event inside the fit, and a user with more than one
address in the baseline. The first makes the evaluation meaningless, the
second changes what S1 even claims.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pandas as pd
import pytest

from minny.baselines.build import BASELINE_CUTOFF, build_baselines
from minny.baselines.model import Baselines

EASTERN = ZoneInfo("America/New_York")


def _event(line, user, ip, ts, template, status=200, method="GET", query=None):
    return {
        "line": line,
        "raw": f"line {line}",
        "ip": ip,
        "user": user,
        "ts": ts,
        "method": method,
        "path": template,
        "base": template,
        "query": query or {},
        "status": status,
        "size": 0,
        "template": template,
        "obj_id": None,
    }


def _frame(rows):
    frame = pd.DataFrame(rows)
    frame["ts"] = pd.to_datetime(frame["ts"], utc=True).dt.tz_convert(EASTERN)
    return frame


@pytest.fixture(scope="module")
def tiny():
    august = datetime(2025, 8, 4, 9, 0, tzinfo=EASTERN)
    february = datetime(2026, 2, 27, 9, 0, tzinfo=EASTERN)
    march = datetime(2026, 3, 15, 11, 7, tzinfo=EASTERN)
    rows = [
        _event(1, "sarah_j", "10.0.5.12", august, "/dashboard"),
        _event(2, "sarah_j", "10.0.5.12", august + timedelta(seconds=5), "/secret.zip"),
        _event(3, "david_m", "10.0.8.45", august, "/dashboard"),
        _event(4, "david_m", "10.0.8.45", august + timedelta(seconds=5), "/secret.zip", status=403),
        _event(5, "david_m", "10.0.8.45", february, "/secret.zip", status=403),
        _event(6, "sarah_j", "10.0.5.12", february, "/api/auth/login", status=401, method="POST"),
        # March. Everything below the fold must be invisible to the fit.
        _event(7, "sarah_j", "10.0.8.45", march, "/api/auth/login", status=401, method="POST"),
        _event(8, "sarah_j", "10.0.8.45", march + timedelta(seconds=2), "/api/admin/role_update", method="POST"),
        _event(9, "david_m", "10.0.8.45", march + timedelta(minutes=20), "/secret.zip"),
    ]
    return _frame(rows)


def test_fit_stops_below_the_cutoff(tiny):
    document = build_baselines(tiny)
    assert document["event_count"] == 6
    max_fitted = datetime.fromisoformat(document["fit_window"]["max_fitted_ts"])
    assert max_fitted < BASELINE_CUTOFF


def test_cutoff_is_an_aware_instant_not_a_wall_clock():
    """The dataset spans a DST change: August lines carry -04:00 and March
    lines -05:00. A naive cutoff, or one pinned to the summer offset, moves the
    boundary by an hour and silently changes which events are held out."""
    august = datetime(2025, 8, 1, 8, 0, tzinfo=EASTERN)
    assert BASELINE_CUTOFF.utcoffset() == timedelta(hours=-5)
    assert august.utcoffset() == timedelta(hours=-4)
    assert BASELINE_CUTOFF.tzinfo is not None
    with pytest.raises(TypeError):
        _ = august.replace(tzinfo=None) < BASELINE_CUTOFF


def test_march_never_reaches_the_baseline(tiny):
    document = build_baselines(tiny)
    david = document["users"]["david_m"]
    # He succeeds on the zip only in March. Counting it would enrol the
    # attacker as an authorised reader of the file he stole.
    assert "/secret.zip" in david["denied_paths"]
    assert "/secret.zip" not in david["allowed_paths"]
    assert "10.0.8.45" not in document["users"]["sarah_j"]["ips"]
    assert "/api/admin/role_update" not in document["global"]["template_freq"]


def test_every_user_has_exactly_one_baseline_ip(tiny):
    document = build_baselines(tiny)
    for name, entry in document["users"].items():
        assert len(entry["ips"]) == 1, f"{name} has {entry['ips']}"


def test_ip_owner_is_the_reverse_map(tiny):
    document = build_baselines(tiny)
    assert document["ip_owner"] == {
        "10.0.5.12": "sarah_j",
        "10.0.8.45": "david_m",
    }


def test_ip_shared_by_two_users_has_no_owner():
    """Unknown is null, never a guess. C's own_ip_takeover variants make this
    case real rather than theoretical."""
    when = datetime(2025, 9, 1, 9, 0, tzinfo=EASTERN)
    frame = _frame(
        [
            _event(1, "sarah_j", "10.0.5.12", when, "/dashboard"),
            _event(2, "david_m", "10.0.5.12", when + timedelta(seconds=1), "/dashboard"),
        ]
    )
    assert build_baselines(frame)["ip_owner"]["10.0.5.12"] is None


def test_denied_paths_exclude_anything_ever_allowed(tiny):
    document = build_baselines(tiny)
    sarah = document["users"]["sarah_j"]
    assert sarah["denied_paths"] == []
    assert "/secret.zip" in sarah["allowed_paths"]


def test_param_keys_ignore_absent_parquet_columns():
    """Parquet widens the query map into a struct, so an absent parameter
    arrives as a None value. Counting it would allow-list every name."""
    when = datetime(2025, 9, 1, 9, 0, tzinfo=EASTERN)
    frame = _frame(
        [
            _event(
                1,
                "sarah_j",
                "10.0.5.12",
                when,
                "/intranet/forum/new",
                status=302,
                method="POST",
                query={"topic": "lunch", "payload": None, "script": None},
            )
        ]
    )
    assert build_baselines(frame)["global"]["param_keys"]["/intranet/forum/new"] == [
        "topic"
    ]


def test_privileged_rule_catches_an_unseen_admin_endpoint(tiny):
    """The baseline window contains no /api/admin/ traffic, so the list is
    empty by design and the recorded rule is what does the work."""
    baselines = Baselines.from_document(build_baselines(tiny))
    assert baselines.privileged_templates == frozenset()
    assert baselines.is_privileged("/api/admin/role_update", "POST", 200)
    assert baselines.is_privileged("/internal/grant_role", "POST", 200)
    assert not baselines.is_privileged("/dashboard", "GET", 200)


def test_hour_hist_is_recorded_but_carries_no_threshold(tiny):
    """It exists for explanation text. Nothing in the file marks an hour as
    anomalous, because legitimate off-hours access is everywhere here."""
    document = build_baselines(tiny)
    assert document["users"]["sarah_j"]["hour_hist"] == {"9": 3}
    assert "hour" not in json_keys(document["global"])


def json_keys(node) -> str:
    return " ".join(node.keys())


def test_unknown_user_gets_an_empty_baseline_rather_than_an_error(tiny):
    baselines = Baselines.from_document(build_baselines(tiny))
    stranger = baselines.user("nobody_at_all")
    assert stranger.ips == frozenset()
    assert baselines.owner_of("192.0.2.1") is None
    assert baselines.frequency("/nowhere") == 0
