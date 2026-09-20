"""Guarantees the numbers said on stage are entitled to rely on.

Four of these decide whether metrics.json means anything. The benign stream
must exclude the real incident, or the false-positive count is measuring our
own success. A variant the detector does catch must score as caught, or
detection is reporting a bug rather than a rate. The table's rows must add up
to the corpus they were drawn from. And the same seed must produce the same
file twice, or nothing in it is reproducible and none of it should be quoted.
"""

from __future__ import annotations

import copy

import pytest

from minny import paths
from minny.baselines.model import Baselines
from minny.detect.signals import SIGNAL_NAMES
from minny.eval import harness, metrics as metrics_module, report, stream
from minny.redteam.catalog import (
    CANONICAL_ATTACKER,
    CANONICAL_VICTIM,
    INCIDENT_LINES,
)
from minny.redteam.operators import OPERATORS

needs_dataset = pytest.mark.skipif(
    not paths.events_path().exists() or not paths.baselines_path().exists(),
    reason="set MINNY_DATA_DIR to the main checkout's data directory",
)

pytestmark = needs_dataset

# Six is enough to exercise every path and small enough that the module runs
# in a couple of seconds. The full 200 belong to `python eval.py`, not to a
# test suite people are meant to run on every commit.
SAMPLE = 6


@pytest.fixture(scope="module")
def baselines():
    return Baselines.load(paths.baselines_path())


@pytest.fixture(scope="module")
def frame():
    return stream.march_frame()


@pytest.fixture(scope="module")
def benign(frame):
    return stream.benign_events(frame)


@pytest.fixture(scope="module")
def variants():
    import json

    return json.loads((paths.data_dir() / "variants.json").read_text("utf-8"))


def _metrics(seed: int, count: int) -> dict:
    """Build a small metrics file the way `python eval.py` builds the real one."""
    import eval as eval_cli

    return eval_cli.run(
        seed=seed,
        count=count,
        variants_path=paths.data_dir() / "variants.json",
        regenerate=False,
    )


@pytest.fixture(scope="module")
def metrics():
    return _metrics(42, SAMPLE)


# --------------------------------------------------------------------------
# The benign stream.
# --------------------------------------------------------------------------


def test_benign_stream_excludes_the_real_incident_lines(frame, benign):
    """The one that keeps the false-positive number honest.

    Counting the 13-15 March lines as noise would score the only thing the
    system is built to find as something it made up, and would roughly double
    the reported alert rate with our own evidence.
    """
    present = {event.line for event in benign}
    assert not present & INCIDENT_LINES

    everything = {event.line for event in stream.march_events(frame)}
    assert INCIDENT_LINES <= everything, "the incident is not in the March window"
    assert len(everything) - len(present) == len(INCIDENT_LINES)


def test_benign_stream_produces_no_alerts(benign, baselines):
    """The false-positive claim, pinned rather than asserted on stage."""
    result = harness.replay(iter(benign), baselines)
    assert result.alerts == []
    assert result.incidents == []


def test_days_are_zero_filled(benign):
    days = stream.days_covered(benign)
    assert len(days) == len(set(days))
    assert days == sorted(days)
    assert all(day.startswith("2026-03") for day in days)


# --------------------------------------------------------------------------
# Scoring one variant.
# --------------------------------------------------------------------------


def test_a_known_detected_variant_scores_as_detected(variants, benign, baselines):
    """v_0001 is a credential takeover onto the victim's own account.

    It puts sarah_j on matthew_r's host, which is the single arithmetic fact
    S1 exists for. If this ever scores as missed, the failure is in the
    harness rather than in the detector.
    """
    variant = next(v for v in variants if v["variant_id"] == "v_0001")
    outcome = harness.evaluate_variant(variant, benign, baselines)

    assert outcome.detected
    assert outcome.incident_id
    assert "S1" in outcome.signals
    assert outcome.alert_count > 0
    assert outcome.log_seconds_to_detect is not None
    assert outcome.log_seconds_to_detect >= 0


def test_detection_means_an_incident_cites_an_injected_line(
    variants, benign, baselines
):
    """The contract's definition, checked against the incident itself."""
    variant = variants[0]
    injected = frozenset(variant["injected_lines"])
    result = harness.replay(
        harness.merged(benign, stream.variant_events(variant)),
        baselines,
        injected=injected,
        variant_id=variant["variant_id"],
    )
    outcome = harness.score(variant, result)

    citing = [
        inc for inc in result.incidents if injected & set(inc["evidence_lines"])
    ]
    assert bool(citing) is outcome.detected
    assert all(inc["labels"]["synthetic"] for inc in citing)
    assert all(inc["labels"]["variant_id"] == variant["variant_id"] for inc in citing)


def test_a_variant_nobody_sees_is_not_credited_with_attribution():
    """Attribution is scored over detected variants only.

    Crediting a miss with a correct name would make attribution climb as
    detection fell, which is the wrong direction for a number to move.
    """
    variant = {
        "variant_id": "v_0000",
        "family": "F1",
        "family_name": "credential_takeover",
        "persona": "careful_insider",
        "operators": [],
        "attacker": "david_m",
        "victim": "sarah_j",
        "injected_lines": [999_001],
        "first_malicious_ts": "2026-03-10T00:00:00-04:00",
    }
    outcome = harness.score(variant, harness.Replay([], [], 0, 0.0))

    assert outcome.detected is False
    assert outcome.attacker_correct is False
    assert outcome.victim_correct is False
    assert outcome.log_seconds_to_detect is None
    assert outcome.signals == ()


# --------------------------------------------------------------------------
# The table adds up.
# --------------------------------------------------------------------------


def test_per_family_counts_sum_to_the_total(metrics):
    rows = metrics["detection"]["by_family"]
    assert sum(row["n"] for row in rows.values()) == metrics["variants"]["total"]
    assert sum(row["detected"] for row in rows.values()) == (
        metrics["detection"]["detected"]
    )


def test_per_operator_counts_sum_to_the_declarations(metrics, variants):
    """Operator rows overlap, so they sum to declarations rather than variants.

    A variant can carry two operators and some carry none, so a row's `n` is
    the number of variants declaring it and the rows together are the number
    of declarations. Both figures are in the file, and this pins them against
    the labels the generator actually wrote.
    """
    rows = metrics["detection"]["by_operator"]
    sample = variants[: metrics["variants"]["total"]]

    assert set(rows) == set(OPERATORS)
    assert sum(row["n"] for row in rows.values()) == (
        metrics["variants"]["declared_operators"]
    )
    assert metrics["variants"]["declared_operators"] == sum(
        len(v["operators"]) for v in sample
    )
    for name, row in rows.items():
        assert row["n"] == sum(1 for v in sample if name in v["operators"])
        assert 0 <= row["detected"] <= row["n"]
        assert row["both_correct"] <= min(row["attacker_correct"], row["victim_correct"])


def test_every_signal_has_a_row(metrics):
    rows = metrics["detection"]["by_signal"]
    assert set(rows) == set(SIGNAL_NAMES)
    # S7 is supporting evidence for the correlator and never raises an alert,
    # so a nonzero count here would mean a signal started emitting.
    assert rows["S7"]["caught"] == 0


def test_detection_without_a_signal_never_exceeds_detection(metrics):
    overall = metrics["detection"]["overall"]
    for row in metrics["detection"]["by_signal"].values():
        assert row["detection_without"] <= overall


# --------------------------------------------------------------------------
# The file itself.
# --------------------------------------------------------------------------


def test_metrics_carries_no_placeholder_flag(metrics):
    """The key that raises the PLACEHOLDER ribbon in the UI.

    Absent by construction rather than deleted afterwards, because a
    placeholder that stopped looking like one is worse than a missing number.
    """
    assert "placeholder" not in metrics
    assert "placeholder_note" not in metrics


def test_metrics_matches_the_contract_shape(metrics):
    for key in (
        "generated_at",
        "command",
        "seed",
        "rule_revision",
        "variants",
        "detection",
        "attribution",
        "false_positives",
        "time_to_detect",
        "real_incident",
        "notes",
    ):
        assert key in metrics, key

    assert metrics["false_positives"]["benign_stream"] == stream.BENIGN_STREAM_LABEL
    assert metrics["command"] == "python eval.py --seed 42"
    assert metrics["notes"], "the attribution ceiling has to be written down"


def test_time_to_detect_keeps_log_time_and_wall_clock_apart(metrics):
    """Two different questions: how long the attacker got, how long we took."""
    ttd = metrics["time_to_detect"]
    assert ttd["median_log_seconds"] >= 0
    assert ttd["p90_log_seconds"] >= ttd["median_log_seconds"]
    assert ttd["wallclock_ms_per_event"] > 0
    assert ttd["wallclock_events"] > ttd["n"]


def test_real_incident_is_detected_and_attributed(metrics):
    real = metrics["real_incident"]
    assert real["detected"] is True
    assert real["named_attacker"] == CANONICAL_ATTACKER
    assert real["named_victim"] == CANONICAL_VICTIM
    assert real["attribution_correct"] is True
    assert real["alert_count"] > 0


def test_report_renders_every_section(metrics):
    text = report.render(metrics)
    for heading in (
        "DETECTION BY OPERATOR",
        "DETECTION BY SIGNAL",
        "SIGNALS FIRED PER OPERATOR",
        "FALSE POSITIVES",
        "TIME TO DETECT",
        "REAL INCIDENT",
        "NOTES",
    ):
        assert heading in text
    for name in OPERATORS:
        assert name in text
    assert "—" not in text and "–" not in text


# --------------------------------------------------------------------------
# Reproducibility.
# --------------------------------------------------------------------------


def _comparable(metrics: dict) -> dict:
    """Everything except what is allowed to differ between two runs.

    The timestamp and the wall-clock latency are measurements of the machine,
    not of the detector. Pinning them would make the suite fail on a busy
    laptop and prove nothing about the numbers anyone quotes.
    """
    stripped = copy.deepcopy(metrics)
    stripped.pop("generated_at")
    for key in ("wallclock_ms_per_event", "wallclock_seconds"):
        stripped["time_to_detect"].pop(key)
    return stripped


def test_seed_42_is_reproducible_across_two_runs(metrics):
    again = _metrics(42, SAMPLE)
    assert _comparable(again) == _comparable(metrics)
    assert again["time_to_detect"]["wallclock_events"] == (
        metrics["time_to_detect"]["wallclock_events"]
    )


def test_quantiles_interpolate_the_same_way_for_both_figures():
    values = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90]
    assert metrics_module._quantile(values, 0.5) == 45.0
    assert metrics_module._quantile(values, 0.9) == 81.0
    assert metrics_module._quantile([], 0.5) is None
    assert metrics_module._quantile([7], 0.9) == 7.0
