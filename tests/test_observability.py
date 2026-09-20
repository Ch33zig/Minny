"""Tests for the Sentry integration and the scrubber.

Two claims are load bearing and both are checked here rather than described.
Without a DSN nothing is transmitted: the SDK is never initialised and no
capture call is made, proved by making both of them explode if they are. And
no payload leaves with an identifier in it: a representative event carrying a
raw log line, an account name, an address, an email and a mailbox body is
scrubbed and then searched, recursively, for every one of them.
"""

from __future__ import annotations

import json

import pytest

from minny import observability as obs
from minny.observability import scrub
from minny.observability.recorder import Recorder

LOG_LINE = (
    '10.0.8.45 - david_m [15/Mar/2026:11:26:59 -0400] '
    '"GET /finance/reports/q1_draft_CONFIDENTIAL.zip HTTP/1.1" 200 4823910'
)
IDENTIFIERS = (
    "david_m",
    "sarah_j",
    "10.0.8.45",
    "10.0.5.12",
    "fe80::1ff:fe23:4567:890a",
    "sarah.jones@example.com",
    "the draft is attached, please do not forward",
)


@pytest.fixture(autouse=True)
def fresh():
    obs.reset_for_tests()
    scrub.SCRUBBER.reset()
    yield
    obs.reset_for_tests()


def _text(payload) -> str:
    return json.dumps(payload, default=str)


# ----------------------------------------------------- nothing without a dsn


def test_no_dsn_means_no_sdk_and_no_events(monkeypatch):
    """The SDK is never touched, and the instrumented path still runs."""
    import sentry_sdk

    def explode(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("sentry_sdk was contacted without a DSN")

    monkeypatch.delenv("SENTRY_BACKEND_DSN", raising=False)
    monkeypatch.setattr(sentry_sdk, "init", explode)
    monkeypatch.setattr(sentry_sdk, "capture_exception", explode)
    monkeypatch.setattr(sentry_sdk, "capture_event", explode, raising=False)
    monkeypatch.setattr(sentry_sdk, "start_transaction", explode)
    monkeypatch.setattr(sentry_sdk, "start_span", explode)
    monkeypatch.setattr(sentry_sdk, "add_breadcrumb", explode)

    state = obs.init()
    assert state["mode"] == "offline"
    assert state["dsn_present"] is False

    with obs.span("replay.evaluate", variant_id="v_0001") as active:
        active.set_data("events", 12)
        obs.breadcrumb("replayed a variant", variant_id="v_0001")
        with obs.span("eval.stream_merge"):
            pass
        try:
            with obs.span("boom"):
                raise ValueError("a failure")
        except ValueError:
            pass

    status = obs.status()
    assert status["enabled"] is False
    assert status["events_sent_without_dsn"] == 0
    # The payloads exist, they were just never transmitted.
    assert status["counts"]["transactions"] == 1
    assert status["counts"]["spans"] == 3


def test_a_span_never_swallows_the_exception_it_records():
    obs.init()
    with pytest.raises(KeyError):
        with obs.span("rule.validate"):
            raise KeyError("missing")
    # Recorded as an error event and as a failed span, but re-raised intact.
    assert obs.RECORDER.counts()["events"] == 1
    transaction = obs.RECORDER.transactions[-1]
    assert transaction["contexts"]["trace"]["status"] == "internal_error"


def test_a_broken_scrubber_drops_the_event_rather_than_passing_it(monkeypatch):
    monkeypatch.setattr(
        scrub.SCRUBBER,
        "_scrub_event",
        lambda event: (_ for _ in ()).throw(RuntimeError("broken")),
    )
    assert scrub.SCRUBBER.before_send({"message": LOG_LINE}) is None


def test_instrumentation_survives_a_span_that_cannot_be_opened(monkeypatch):
    """A failure inside the machinery is not a failure of the caller."""
    import minny.observability.spans as spans

    monkeypatch.setattr(
        spans, "Span", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no"))
    )
    obs.init()
    with obs.span("replay.evaluate") as active:
        active.set_data("events", 1)
        active.add("pace.waits", 3)
    assert obs.RECORDER.counts()["transactions"] == 0


# ------------------------------------------------------------- the scrubber


def _representative_event() -> dict:
    """One payload carrying every kind of identifier this dataset holds."""
    return {
        "event_id": "0f3c21" * 5 + "ab",
        "level": "error",
        "transaction": "replay.evaluate",
        "user": {"id": "sarah_j", "ip_address": "10.0.5.12"},
        "message": f"detector raised while replaying {LOG_LINE}",
        "exception": {
            "values": [
                {
                    "type": "KeyError",
                    "value": (
                        "no baseline for david_m at 10.0.8.45, known "
                        "10.0.5.12, contact sarah.jones@example.com"
                    ),
                }
            ]
        },
        "breadcrumbs": {
            "values": [
                {
                    "category": "detect",
                    "message": "S1 fired for sarah_j from 10.0.8.45",
                    "data": {
                        "user": "sarah_j",
                        "ip": "10.0.8.45",
                        "ipv6": "fe80::1ff:fe23:4567:890a",
                        "raw": LOG_LINE,
                    },
                }
            ]
        },
        "spans": [
            {
                "op": "replay",
                "description": "replay.evaluate",
                "data": {
                    "variant_id": "v_0001",
                    "rule_id": "R001",
                    "events": 180800,
                    "explanation": (
                        "sarah_j used 10.0.8.45, which belongs to david_m"
                    ),
                },
            }
        ],
        "extra": {
            "evidence_lines": [168343],
            "subject": "Q1 draft",
            "body": "the draft is attached, please do not forward",
            "mailbox": "sarah.jones@example.com",
        },
        "tags": {"service": "worker", "attacker": "david_m"},
    }


@pytest.mark.parametrize("identifier", IDENTIFIERS)
def test_the_scrubber_removes_every_identifier(identifier):
    cleaned = scrub.SCRUBBER.before_send(_representative_event())
    assert identifier not in _text(cleaned)


def test_the_scrubber_removes_the_raw_log_line_as_a_unit():
    cleaned = scrub.SCRUBBER.before_send(_representative_event())
    text = _text(cleaned)
    assert scrub.LOG_TOKEN in text
    # Not merely the address and the account picked out of it: the request
    # path, the byte count and the timestamp go with them.
    assert "q1_draft_CONFIDENTIAL" not in text
    assert "15/Mar/2026" not in text


def test_the_user_section_is_dropped_not_rewritten():
    cleaned = scrub.SCRUBBER.before_send(_representative_event())
    assert "user" not in cleaned


def test_mailbox_content_goes_by_key_not_by_pattern():
    cleaned = scrub.SCRUBBER.before_send(_representative_event())
    assert cleaned["extra"]["body"] == scrub.REDACTED
    assert cleaned["extra"]["subject"] == scrub.REDACTED


def test_a_registered_name_is_removed_even_without_the_dataset_shape():
    scrub.SCRUBBER.register(["svc-ingest-07"])
    cleaned = scrub.SCRUBBER.before_send({"message": "svc-ingest-07 failed"})
    assert "svc-ingest-07" not in cleaned["message"]


def test_the_scrubber_keeps_the_context_worth_keeping():
    """Over-scrubbing makes the span useless, which is its own failure."""
    cleaned = scrub.SCRUBBER.before_send(_representative_event())
    span = cleaned["spans"][0]
    assert span["description"] == "replay.evaluate"
    assert span["data"]["variant_id"] == "v_0001"
    assert span["data"]["rule_id"] == "R001"
    assert span["data"]["events"] == 180800
    assert cleaned["extra"]["evidence_lines"] == [168343]
    assert cleaned["tags"]["service"] == "worker"


def test_a_clock_time_is_not_mistaken_for_an_ipv6_address():
    cleaned = scrub.scrub_text("opened at 11:26:59 and closed at 22:04:55")
    assert cleaned == "opened at 11:26:59 and closed at 22:04:55"


def test_an_oversized_value_is_truncated():
    cleaned = scrub.scrub_text("x" * (scrub.MAX_VALUE_CHARS + 50))
    assert cleaned.endswith(scrub.TRUNCATED)
    assert len(cleaned) < scrub.MAX_VALUE_CHARS + 50


def test_breadcrumbs_are_scrubbed_on_their_own_hook():
    """Scrubbing errors does not sanitise breadcrumbs; they are a separate
    payload with a separate hook, and this is the test that says so."""
    crumb = scrub.before_breadcrumb(
        {"message": f"S1 for sarah_j from 10.0.8.45", "data": {"raw": LOG_LINE}}
    )
    assert "sarah_j" not in _text(crumb)
    assert "10.0.8.45" not in _text(crumb)
    assert crumb["data"]["raw"] == scrub.REDACTED


def test_the_scrub_report_counts_what_it_removed():
    scrub.SCRUBBER.before_send(_representative_event())
    report = scrub.describe()
    assert report["redactions"]["log_line"] >= 1
    assert report["redactions"]["ip"] >= 1
    assert report["redactions"]["username"] >= 1
    assert report["redactions"]["sensitive_key"] >= 1
    assert report["order"][0] == "log_line"
    assert report["send_default_pii"] is False


# -------------------------------------------------------------- the offline
# ------------------------------------------------------------------ payload


def test_the_offline_payload_is_written_scrubbed(tmp_path):
    obs.init()
    with obs.span("eval.variant", variant_id="v_0001") as active:
        active.set_data("note", f"replaying {LOG_LINE}")
    written = obs.flush(tmp_path)
    assert set(written) >= {
        "transactions.json",
        "events.json",
        "spans.json",
        "scrub_report.json",
    }
    body = (tmp_path / "transactions.json").read_text(encoding="utf-8")
    assert "david_m" not in body
    assert "10.0.8.45" not in body
    assert scrub.LOG_TOKEN in body
    assert "eval.variant" in body


def test_the_recorder_drops_oldest_rather_than_growing_without_bound():
    recorder = Recorder(max_transactions=3, max_events=2)
    for n in range(10):
        recorder.record_transaction({"n": n})
        recorder.record_timing("eval.variant", float(n))
    counts = recorder.counts()
    assert counts["transactions"] == 3
    assert counts["dropped"]["transactions"] == 7
    # The distribution survives the drop, which is the number anyone reads.
    assert recorder.span_stats()["eval.variant"]["count"] == 10
    assert recorder.span_stats()["eval.variant"]["max_ms"] == 9.0


def test_span_counters_accumulate_without_a_span_per_iteration():
    obs.init()
    with obs.span("stream.replay") as active:
        for _ in range(500):
            active.add("pace.waits")
            active.add("pace.requested_ms", 2.0)
    data = obs.RECORDER.transactions[-1]["contexts"]["trace"]["data"]
    assert data["pace.waits"] == 500
    assert data["pace.requested_ms"] == 1000.0
    # One span, not five hundred.
    assert obs.RECORDER.counts()["spans"] == 1
