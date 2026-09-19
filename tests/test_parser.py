"""Parser guarantees the other three tracks are entitled to rely on."""

from __future__ import annotations

from pathlib import Path

import pytest

from minny.parser import EXPECTED_ROWS, normalize_template, parse_file, parse_line

LOGS = Path("data/logs.txt")

needs_dataset = pytest.mark.skipif(
    not LOGS.exists(), reason="data/logs.txt is shared out of band"
)


def test_parses_a_canonical_line():
    raw = (
        "10.0.8.45 - david_m [15/Mar/2026:11:26:59 -0400] "
        '"GET /finance/reports/q1_draft_CONFIDENTIAL.zip HTTP/1.1" 200 8459200'
    )
    event = parse_line(168338, raw)

    assert event.line == 168338
    assert event.ip == "10.0.8.45"
    assert event.user == "david_m"
    assert event.status == 200
    assert event.size == 8459200
    assert event.query == {}
    assert event.raw == raw, "evidence display shows raw bytes, not a re-render"


def test_parses_query_parameters():
    raw = (
        "10.0.8.45 - david_m [15/Mar/2026:10:18:52 -0400] "
        '"POST /intranet/forum/new?topic=parking_issues&script=success '
        'HTTP/1.1" 302 112'
    )
    event = parse_line(168332, raw)

    assert event.base == "/intranet/forum/new"
    assert event.query == {"topic": "parking_issues", "script": "success"}


def test_unauthenticated_user_becomes_none():
    raw = '1.2.3.4 - - [01/Aug/2025:08:00:57 -0400] "GET /logout HTTP/1.1" 302 0'
    assert parse_line(1, raw).user is None


def test_timestamps_are_timezone_aware():
    raw = (
        "10.0.5.12 - sarah_j [15/Mar/2026:11:07:57 -0400] "
        '"POST /api/admin/role_update HTTP/1.1" 200 85'
    )
    assert parse_line(1, raw).ts.utcoffset() is not None


@pytest.mark.parametrize(
    ("base", "expected_template", "expected_id"),
    [
        ("/intranet/forum/view/1042", "/intranet/forum/view/{id}", 1042),
        ("/intranet/forum/edit/1042", "/intranet/forum/edit/{id}", 1042),
        ("/assets/avatar_1042.png", "/assets/avatar_{id}.png", 1042),
        ("/dashboard", "/dashboard", None),
        ("/finance/reports/q1_draft_CONFIDENTIAL.zip", None, None),
    ],
)
def test_template_normalization(base, expected_template, expected_id):
    template, obj_id = normalize_template(base)
    assert template == (expected_template or base)
    assert obj_id == expected_id


def test_malformed_line_raises():
    with pytest.raises(ValueError):
        parse_line(1, "this is not a log line")


@needs_dataset
def test_whole_dataset_parses():
    events = parse_file(LOGS)
    assert len(events) == EXPECTED_ROWS
    assert events[0].line == 1
    assert events[-1].line == EXPECTED_ROWS


@needs_dataset
def test_known_incident_lines_are_where_the_case_file_says():
    """The case file cites these by number, so pin them here.

    If the dataset is ever swapped, this test fails loudly instead of the
    case file quietly citing the wrong evidence.
    """
    events = parse_file(LOGS)

    # David's third payload attempt is the one that succeeds.
    assert events[168331].user == "david_m"
    assert events[168331].base == "/intranet/forum/new"
    assert events[168331].status == 302

    # Sarah views the post, and one second later her session escalates.
    assert events[168334].template == "/intranet/forum/view/{id}"
    assert events[168334].obj_id == 1042
    assert events[168335].base == "/api/admin/role_update"
    assert events[168335].user == "sarah_j"

    # David then takes the file he had been denied 80 times.
    assert events[168337].user == "david_m"
    assert events[168337].status == 200
    assert "q1_draft_CONFIDENTIAL" in events[168337].base

    # That night her account is used from his workstation.
    assert events[168342].user == "sarah_j"
    assert events[168342].ip == "10.0.8.45"
