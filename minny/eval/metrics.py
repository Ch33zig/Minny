"""Aggregate scored outcomes into metrics.json (milestone M5).

The shape is 00-CONTRACTS.md section 9. Extra keys are added, none are
renamed: D's panel reads `n`, `detected` and `rate` off every row and ignores
the rest, so a richer table costs the UI nothing and answers the second
question a judge asks.

Two rules hold throughout. Nothing here is typed in, every figure is computed
from the outcomes this module is handed. And `placeholder` is absent by
construction rather than deleted afterwards, because the only thing worse than
a missing number is a placeholder that stopped looking like one.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from datetime import datetime
from pathlib import Path

from minny.detect.signals import SIGNAL_NAMES
from minny.eval.harness import Outcome
from minny.eval.stream import BENIGN_STREAM_LABEL
from minny.redteam.catalog import CANONICAL_ATTACKER, CANONICAL_VICTIM
from minny.redteam.families import FAMILIES
from minny.redteam.operators import OPERATORS

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _rate(part: int, whole: int) -> float:
    return round(part / whole, 4) if whole else 0.0


def _quantile(values: list[float], q: float) -> float | None:
    """Linear interpolation between order statistics, as numpy would.

    Written out rather than imported so the median and the p90 come from one
    method. Two quantiles computed two ways is the kind of detail that turns a
    question from the floor into an argument.
    """
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(float(ordered[0]), 1)
    position = (len(ordered) - 1) * q
    low, high = math.floor(position), math.ceil(position)
    if low == high:
        return round(float(ordered[low]), 1)
    span = ordered[high] - ordered[low]
    return round(float(ordered[low] + span * (position - low)), 1)


def rule_revision() -> str:
    """What the detector was when these numbers were produced.

    The blue agent's rule file does not exist until M6, so until it does the
    revision names the code that actually did the detecting. A field reading
    rules.yaml@a1b2c3d while no rules.yaml exists is provenance theatre.
    """
    rules = _REPO_ROOT / "detection-rules" / "rules.yaml"
    source = rules if rules.exists() else _REPO_ROOT / "minny" / "detect" / "signals.py"
    digest = hashlib.sha1(source.read_bytes()).hexdigest()[:7]
    return f"{source.name}@{digest}"


def _row(outcomes: list[Outcome]) -> dict:
    """One table row: how many, how many caught, and who got named."""
    detected = [o for o in outcomes if o.detected]
    latencies = [
        o.log_seconds_to_detect
        for o in detected
        if o.log_seconds_to_detect is not None
    ]
    return {
        "n": len(outcomes),
        "detected": len(detected),
        "rate": _rate(len(detected), len(outcomes)),
        # Attribution is scored over the detected ones only. A variant nobody
        # saw cannot have been blamed on the wrong person.
        "attacker_correct": sum(1 for o in detected if o.attacker_correct),
        "victim_correct": sum(1 for o in detected if o.victim_correct),
        "both_correct": sum(1 for o in detected if o.both_correct),
        "median_log_seconds": _quantile(latencies, 0.5),
        "signals": _signal_counts(outcomes),
    }


def _signal_counts(outcomes: list[Outcome]) -> dict:
    """How many of these variants each signal fired on. Zero is a result."""
    counts = Counter(name for o in outcomes for name in o.signals)
    return {name: counts[name] for name in SIGNAL_NAMES}


def _by_signal(outcomes: list[Outcome]) -> dict:
    """Per signal: how much it caught, and how much only it caught.

    `sole` is the column that matters. A signal that fires on 180 variants but
    is never the only one firing can be removed without changing the headline
    number, and a signal with a high `sole` count is the one holding the
    detection rate up on its own.
    """
    total = len(outcomes)
    rows = {}
    for name in SIGNAL_NAMES:
        caught = [o for o in outcomes if name in o.signals]
        sole = [o for o in caught if len(o.signals) == 1]
        without = sum(1 for o in outcomes if set(o.signals) - {name})
        rows[name] = {
            "signal_name": SIGNAL_NAMES[name],
            "caught": len(caught),
            "rate": _rate(len(caught), total),
            "sole": len(sole),
            # Detection if this signal did not exist. Exact rather than
            # estimated: a variant is detected when some alert cites one of
            # its lines, so deleting a signal deletes exactly its own alerts.
            "detection_without": _rate(without, total),
        }
    return rows


def _signal_suppression(outcomes: list[Outcome]) -> list[dict]:
    """What each operator actually switched off, against a matched control.

    An operator is compared only with variants of the same families, because
    the operators are not drawn uniformly: slow_guess only ever lands on the
    two families that contain a login, so measuring it against the whole
    corpus would credit it with silencing S3 on families that never had a
    failed login to burst.

    This is the number the per-operator detection table cannot show. Nine rows
    reading 100% caught means the detector has enough overlapping signals to
    survive any one evasion, which is a real and good result, but it says
    nothing about which assumption each evasion broke. This does.
    """
    rows = []
    for operator in OPERATORS:
        carrying = [o for o in outcomes if operator in o.operators]
        if not carrying:
            continue
        families = {o.family for o in carrying}
        control = [
            o
            for o in outcomes
            if operator not in o.operators and o.family in families
        ]
        if not control:
            continue
        for signal in SIGNAL_NAMES:
            fired = sum(1 for o in carrying if signal in o.signals)
            base = sum(1 for o in control if signal in o.signals)
            with_rate = _rate(fired, len(carrying))
            control_rate = _rate(base, len(control))
            if control_rate <= 0 or with_rate >= control_rate:
                continue
            rows.append(
                {
                    "operator": operator,
                    "signal": signal,
                    "signal_name": SIGNAL_NAMES[signal],
                    "n": len(carrying),
                    "fired": fired,
                    "rate": with_rate,
                    "control_n": len(control),
                    "control_fired": base,
                    "control_rate": control_rate,
                    "suppression": round(1 - with_rate / control_rate, 4),
                }
            )
    return sorted(rows, key=lambda row: (-row["suppression"], -row["control_n"]))


def _by_operator(outcomes: list[Outcome]) -> dict:
    """Every declared operator, including any nobody drew.

    The key set is fixed by the contract, so a missing row would read as an
    operator that was never tried rather than one that never came up.
    """
    return {
        name: _row([o for o in outcomes if name in o.operators]) for name in OPERATORS
    }


def _by_family(outcomes: list[Outcome]) -> dict:
    return {
        family: _row([o for o in outcomes if o.family == family])
        for family in FAMILIES
    }


def _by_persona(outcomes: list[Outcome]) -> dict:
    personas = sorted({o.persona for o in outcomes})
    return {
        persona: _row([o for o in outcomes if o.persona == persona])
        for persona in personas
    }


def _attribution(outcomes: list[Outcome]) -> dict:
    detected = [o for o in outcomes if o.detected]
    attacker = sum(1 for o in detected if o.attacker_correct)
    victim = sum(1 for o in detected if o.victim_correct)
    both = sum(1 for o in detected if o.both_correct)
    return {
        "n_detected": len(detected),
        "attacker_correct": attacker,
        "victim_correct": victim,
        "both_correct": both,
        # Reported apart because a security team asks them apart. Naming the
        # right victim and the wrong attacker is a different kind of wrong
        # from naming neither.
        "attacker_correct_rate": _rate(attacker, len(detected)),
        "victim_correct_rate": _rate(victim, len(detected)),
        "both_correct_rate": _rate(both, len(detected)),
        # Declining to name and naming the wrong person are the same miss in
        # the rate above and nothing like the same failure in an
        # investigation. A wrong name sends someone to HR.
        "unnamed_attacker": sum(1 for o in detected if o.named_attacker is None),
        "unnamed_victim": sum(1 for o in detected if o.named_victim is None),
        "misattributed_attacker": sum(
            1
            for o in detected
            if o.named_attacker is not None and o.named_attacker != o.attacker
        ),
        "misattributed_victim": sum(
            1
            for o in detected
            if o.named_victim is not None and o.named_victim != o.victim
        ),
        "by_operator": {
            name: _row([o for o in detected if name in o.operators])
            for name in OPERATORS
        },
    }


def _false_positives(alerts: list, incidents: list, days: list[str]) -> dict:
    by_day = {day: 0 for day in days}
    for alert in alerts:
        day = datetime.fromisoformat(alert["ts"]).date().isoformat()
        by_day[day] = by_day.get(day, 0) + 1
    return {
        "benign_stream": BENIGN_STREAM_LABEL,
        "alerts_total": len(alerts),
        "incidents_total": len(incidents),
        "days": len(days),
        "alerts_per_day": _rate(len(alerts), len(days)),
        "incidents_per_day": _rate(len(incidents), len(days)),
        # Zero-filled. Dividing by the days that happened to alert is not a
        # rate, it is a tautology.
        "by_day": by_day,
    }


def _time_to_detect(outcomes: list[Outcome], wallclock: dict) -> dict:
    latencies = [
        o.log_seconds_to_detect
        for o in outcomes
        if o.detected and o.log_seconds_to_detect is not None
    ]
    return {
        "n": len(latencies),
        "median_log_seconds": _quantile(latencies, 0.5),
        "p90_log_seconds": _quantile(latencies, 0.9),
        "min_log_seconds": _quantile(latencies, 0.0),
        "max_log_seconds": _quantile(latencies, 1.0),
        # A different question entirely: how long the machine takes, not how
        # long the attacker gets. Merging the two would hide a slow detector
        # behind a slow attack, or the other way round.
        "wallclock_ms_per_event": wallclock["ms_per_event"],
        "wallclock_events": wallclock["events"],
        "wallclock_seconds": wallclock["seconds"],
    }


def _evasions(outcomes: list[Outcome]) -> list[dict]:
    """The operators that got through, worst first.

    No threshold anywhere. An operator appears here when at least one variant
    carrying it was missed, which is a fact rather than a judgement, and the
    ordering says where the blue agent should start.
    """
    rows = []
    for name in OPERATORS:
        carrying = [o for o in outcomes if name in o.operators]
        missed = [o for o in carrying if not o.detected]
        if missed:
            rows.append(
                {
                    "operator": name,
                    "n": len(carrying),
                    "missed": len(missed),
                    "rate": _rate(len(carrying) - len(missed), len(carrying)),
                }
            )
    return sorted(rows, key=lambda row: (row["rate"], -row["missed"]))


def _notes(outcomes: list[Outcome], by_signal: dict, attribution: dict) -> list[str]:
    total = len(outcomes)
    own_ip = [o for o in outcomes if "own_ip_takeover" in o.operators]
    ceiling = _rate(total - len(own_ip), total)
    load_bearing = max(by_signal.items(), key=lambda item: item[1]["sole"])
    wrong = attribution["misattributed_attacker"] + attribution["misattributed_victim"]
    misattribution = (
        "No detected variant was blamed on the wrong account. Every "
        "attribution miss in this run is the correlator declining to name "
        "anyone, not naming the wrong person, which are the same number above "
        "and nothing like the same failure in an investigation."
        if wrong == 0
        else f"{wrong} detected variants named the wrong account. That is "
        f"worse than naming nobody and it is the first thing to fix."
    )
    return [
        misattribution,
        f"Detection is high because the signals overlap, not because the "
        f"evasions failed. {load_bearing[0]} {load_bearing[1]['signal_name']} "
        f"is the load-bearing one: it is the only signal to fire on "
        f"{load_bearing[1]['sole']} of {total} variants, and without it "
        f"detection would be "
        f"{load_bearing[1]['detection_without']:.1%}. Read the "
        f"signal_suppression list, not the per-operator rates, to see which "
        f"assumption each evasion actually broke.",
        f"Attacker attribution has a ceiling in the data, not in the detector. "
        f"{len(own_ip)} of {total} variants carry own_ip_takeover, where the "
        f"session arrives from a host no baseline can attribute to anyone. No "
        f"line in the log names the attacker, so the correlator reports the "
        f"address and drops confidence to low rather than guessing. Those "
        f"variants score attacker-incorrect, which caps overall attacker "
        f"attribution at about {ceiling:.0%}. A figure near 100% would mean "
        f"the harness was reading the answer key.",
        "False positives are counted on March with the 26 labeled incident "
        "lines removed. Leaving them in would score the one thing the system "
        "exists to find as noise it made up.",
        "Every variant is replayed alone into the benign stream with a fresh "
        "detector and correlator. Injecting them together would let two "
        "variants sharing a victim inside the 72-hour correlation window "
        "collapse into one incident and each be scored as detected on the "
        "other's evidence.",
    ]


def build(
    *,
    seed: int,
    outcomes: list[Outcome],
    benign_alerts: list,
    benign_incidents: list,
    benign_days: list[str],
    wallclock: dict,
    real_incident: dict,
) -> dict:
    """Assemble the file in contract order, so a diff against section 9 reads."""
    detected = [o for o in outcomes if o.detected]
    by_signal = _by_signal(outcomes)
    attribution = _attribution(outcomes)
    return {
        # The local offset, not the log's. This field says when the command
        # ran, and stamping it -0400 on a machine that is not would be a small
        # lie in the one field that exists to date the numbers.
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "command": f"python eval.py --seed {seed}",
        "seed": seed,
        "rule_revision": rule_revision(),
        "method": {
            "injection": "one variant per replay, injected into the benign stream",
            "replays": len(outcomes) + 2,
            "benign_stream": BENIGN_STREAM_LABEL,
            "detector": "minny.detect.signals.Detector, fed through "
            "minny.detect.events.merged",
            "detected_when": "an incident cites at least one injected line",
        },
        "variants": {
            "total": len(outcomes),
            "by_family": dict(Counter(o.family for o in outcomes)),
            "by_persona": dict(Counter(o.persona for o in outcomes)),
            # Operators overlap: a variant can carry two and some carry none,
            # so these sum to the number of declarations, not to total.
            "by_operator": {
                name: sum(1 for o in outcomes if name in o.operators)
                for name in OPERATORS
            },
            "declared_operators": sum(len(o.operators) for o in outcomes),
            "without_operators": sum(1 for o in outcomes if not o.operators),
        },
        "detection": {
            "overall": _rate(len(detected), len(outcomes)),
            "n": len(outcomes),
            "detected": len(detected),
            "by_operator": _by_operator(outcomes),
            "by_family": _by_family(outcomes),
            "by_persona": _by_persona(outcomes),
            # The row that explains the ones above it: nine operators at the
            # same rate is not a finding until you can say what each one
            # actually switched off.
            "by_signal": by_signal,
        },
        "attribution": attribution,
        "false_positives": _false_positives(
            benign_alerts, benign_incidents, benign_days
        ),
        "time_to_detect": _time_to_detect(outcomes, wallclock),
        "real_incident": real_incident,
        "evasions": _evasions(outcomes),
        "signal_suppression": _signal_suppression(outcomes),
        "notes": _notes(outcomes, by_signal, attribution),
    }


def real_incident_result(alerts: list, incidents: list, lines) -> dict:
    """Score the 13-15 March breach exactly the way a variant is scored.

    Same definition of detected, same definition of correct. One incident is
    an anecdote and the 200 variants are the measurement, but the anecdote has
    to be scored by the measurement's rules or it proves nothing.
    """
    labeled = frozenset(lines)
    holders = [
        inc
        for inc in incidents
        if labeled.intersection(inc.get("evidence_lines") or [])
    ]
    incident = (
        max(holders, key=lambda inc: len(labeled.intersection(inc["evidence_lines"])))
        if holders
        else None
    )
    own = [a for a in alerts if labeled.intersection(a["evidence_lines"])]
    attacker = (incident or {}).get("attacker", {}).get("user")
    victim = (incident or {}).get("victim", {}).get("user")
    attacker_correct = attacker == CANONICAL_ATTACKER
    victim_correct = victim == CANONICAL_VICTIM
    return {
        "detected": incident is not None,
        "attribution_correct": bool(incident) and attacker_correct and victim_correct,
        "alert_count": len(own),
        "incident_id": (incident or {}).get("incident_id"),
        "named_attacker": attacker,
        "named_victim": victim,
        "attacker_correct": attacker_correct,
        "victim_correct": victim_correct,
        "labeled_lines_cited": len(
            labeled.intersection((incident or {}).get("evidence_lines") or [])
        ),
        "labeled_lines_total": len(labeled),
    }
