"""Replay a stream through the live detector and score what came back (M5).

The harness owns no detection logic. It builds a `Detector` and a
`Correlator`, feeds them one event at a time through the same
`feed`/`add` pair the replay engine uses, and reads the incidents out. If a
signal changes, this file does not, and the numbers move on their own.

**Every variant is replayed alone.** 200 variants injected into one stream
would share a correlation window, and the correlator joins alerts on shared
entities: two variants naming the same victim inside 72 hours would collapse
into one incident and each would be scored as detected on the other's
evidence. That is not a small inflation, it is the measurement measuring
itself. One variant, one full replay of the benign stream, one fresh detector,
201 times. It costs about twenty seconds, which is a cheap price for a number
nobody has to caveat.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime

from minny.baselines.model import Baselines
from minny.detect.correlator import Correlator
from minny.detect.events import DetectEvent, merged
from minny.detect.signals import Detector
from minny.eval.stream import variant_events


@dataclass(frozen=True)
class Replay:
    """What one pass through the detector produced."""

    alerts: list
    incidents: list
    events: int
    seconds: float


@dataclass(frozen=True)
class Outcome:
    """One variant, scored. The row behind every cell of the report."""

    variant_id: str
    family: str
    family_name: str
    persona: str
    operators: tuple[str, ...]
    attacker: str
    victim: str
    detected: bool
    incident_id: str | None
    named_attacker: str | None
    named_victim: str | None
    attacker_correct: bool
    victim_correct: bool
    alert_count: int
    log_seconds_to_detect: float | None
    # Which signals fired on this variant's own lines. Nine operator rows all
    # reading 100% says nothing about which evasion worked; this is what says
    # it, because an operator that kills one signal while another picks the
    # variant up is still an evasion and still the thing the blue agent has
    # to close.
    signals: tuple[str, ...]
    events: int
    seconds: float

    @property
    def both_correct(self) -> bool:
        return self.attacker_correct and self.victim_correct


def replay(
    events,
    baselines: Baselines,
    *,
    injected: frozenset[int] = frozenset(),
    variant_id: str | None = None,
) -> Replay:
    """Stream events through the detector and the correlator together.

    Timed around the feed loop only. Loading parquet and merging streams is
    harness overhead and folding it into a per-event latency would flatter the
    detector by a factor nobody could reproduce.
    """
    detector = Detector(baselines)
    correlator = Correlator()
    alerts: list = []
    count = 0

    started = time.perf_counter()
    for event in events:
        count += 1
        for alert in detector.feed(event):
            if injected and injected.intersection(alert["evidence_lines"]):
                # The correlator reads these off the alerts when it builds the
                # incident, so the tag has to land before the alert is claimed.
                alert["synthetic"] = True
                alert["variant_id"] = variant_id
            correlator.add(alert)
            alerts.append(alert)
    seconds = time.perf_counter() - started

    return Replay(alerts, correlator.incidents(), count, seconds)


def _ts(value) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(value)


def _best_incident(incidents: list, injected: frozenset[int]) -> dict | None:
    """The incident that actually tells this variant's story.

    Detection only asks whether some incident cites an injected line, but
    attribution has to name one, so ties go to the incident holding the most
    of the variant's evidence and then to the one that opened first.
    """
    holders = [
        incident
        for incident in incidents
        if injected.intersection(incident.get("evidence_lines") or [])
    ]
    if not holders:
        return None
    return max(
        holders,
        key=lambda inc: (
            len(injected.intersection(inc["evidence_lines"])),
            -_ts(inc["opened_ts"]).timestamp(),
        ),
    )


def score(variant: dict, result: Replay) -> Outcome:
    """Turn one replay into one row.

    Detected means an incident cites at least one injected line, per
    00-CONTRACTS.md section 9. Time to detect runs from the variant's
    `first_malicious_ts` to the first alert that cites an injected line, in
    log time, and is undefined rather than zero for a variant nobody caught.
    """
    injected = frozenset(variant["injected_lines"])
    own_alerts = [
        alert
        for alert in result.alerts
        if injected.intersection(alert["evidence_lines"])
    ]
    incident = _best_incident(result.incidents, injected)

    named_attacker = (incident or {}).get("attacker", {}).get("user")
    named_victim = (incident or {}).get("victim", {}).get("user")

    log_seconds = None
    if own_alerts:
        first_alert = min(_ts(alert["ts"]) for alert in own_alerts)
        log_seconds = (
            first_alert - _ts(variant["first_malicious_ts"])
        ).total_seconds()

    return Outcome(
        variant_id=variant["variant_id"],
        family=variant["family"],
        family_name=variant["family_name"],
        persona=variant["persona"],
        operators=tuple(variant["operators"]),
        attacker=variant["attacker"],
        victim=variant["victim"],
        detected=incident is not None,
        incident_id=(incident or {}).get("incident_id"),
        named_attacker=named_attacker,
        named_victim=named_victim,
        # Scored only where there is an incident to be wrong about. Crediting
        # a miss with a correct name would make attribution rise as detection
        # falls, which is the wrong direction for a number to move.
        attacker_correct=bool(incident) and named_attacker == variant["attacker"],
        victim_correct=bool(incident) and named_victim == variant["victim"],
        alert_count=len(own_alerts),
        log_seconds_to_detect=log_seconds,
        signals=tuple(sorted({alert["signal"] for alert in own_alerts})),
        events=result.events,
        seconds=result.seconds,
    )


def evaluate_variant(
    variant: dict, benign: list[DetectEvent], baselines: Baselines
) -> Outcome:
    """Inject one variant into the benign stream and score the result."""
    stream = merged(benign, variant_events(variant))
    result = replay(
        stream,
        baselines,
        injected=frozenset(variant["injected_lines"]),
        variant_id=variant["variant_id"],
    )
    return score(variant, result)


def evaluate_all(
    variants: list[dict],
    benign: list[DetectEvent],
    baselines: Baselines,
    *,
    progress=None,
) -> list[Outcome]:
    outcomes = []
    for index, variant in enumerate(variants, start=1):
        outcomes.append(evaluate_variant(variant, benign, baselines))
        if progress is not None:
            progress(index, len(variants))
    return outcomes
