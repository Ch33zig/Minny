"""What the blue agent is allowed to look at (milestone M6).

The split is the point of the whole milestone. A rule written while looking
at the variants it is later scored on has not been validated, it has been
fitted, and the gate that passes it is a rubber stamp. So the evidence packet
assembled here is deliberately narrow:

* the **training variants**, the seed-42 batch the evaluation already scored,
  restricted to one persona. The held-out set the gate uses is generated from
  different seeds *and* from the two personas left over, so nothing the
  proposer read can come back around as a passing grade.
* the **features those variants produced**, which is exactly what a rule
  sees: `minny.detect.rules.features` and nothing richer. A proposer
  reasoning over fields a rule cannot read would write rules that cannot be
  expressed.
* a **sample of benign March**, so the proposer can tell whether the
  threshold it is about to write separates an attack from a Monday morning.
* the **one real incident**, because that is what a defender actually has on
  the day, and writing a rule from it alone is the failure mode M6 exists to
  demonstrate.

Nothing here decides anything. It gathers, records where each row came from,
and hands it over.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from minny import paths
from minny.detect import rules as dsl
from minny.detect.events import DetectEvent, from_frame
from minny.eval.stream import variant_events
from minny.redteam.catalog import INCIDENT_LINES

# One persona trains, the other two are held out. The seed-42 batch spreads
# every operator across all three, so taking `careful_insider` for training
# leaves a held-out pool differing from it in persona as well as in seed,
# which is what 00-CONTRACTS.md section 10 asks of the first gate check.
TRAINING_PERSONAS: tuple[str, ...] = ("careful_insider",)
HELDOUT_PERSONAS: tuple[str, ...] = (
    "impatient_insider",
    "outsider_with_stolen_credentials",
)

# Enough benign traffic to price a threshold against, small enough that the
# proposer's own scoring pass stays under a second. The gate measures false
# positives on all of March; this is the proposer's working sample.
BENIGN_SAMPLE = 6000


@dataclass(frozen=True)
class Evidence:
    """One evaded operator, everything known about it, and nothing else."""

    operator: str
    signal: str | None
    signal_name: str | None
    suppression: dict | None
    seeds: tuple[int, ...]
    personas: tuple[str, ...]
    variants: tuple[dict, ...]
    variant_features: tuple[dict, ...]
    benign: tuple
    benign_features: tuple[dict, ...]
    incident_features: tuple[dict, ...]

    def events(self) -> list[DetectEvent]:
        return [event for variant in self.variants for event in variant_events(variant)]

    def summary(self) -> dict:
        """The provenance a proposal carries, so a reader can check the split."""
        return {
            "operator": self.operator,
            "evaded_signal": self.signal,
            "evaded_signal_name": self.signal_name,
            "suppression": self.suppression,
            "training_variants": len(self.variants),
            "training_seeds": list(self.seeds),
            "training_personas": list(self.personas),
            "training_variant_ids": [v["variant_id"] for v in self.variants],
            "benign_sample_events": len(self.benign),
            "incident_lines": len(self.incident_features),
        }


def jsonable(row: dict) -> dict:
    """One feature row as JSON. `ts` is a datetime and `signal` is a set."""
    return {
        "line": row.get("line"),
        "ts": row["ts"].isoformat() if row.get("ts") is not None else None,
        "user": row.get("user"),
        "ip": row.get("ip"),
        "ip_owner": row.get("ip_owner"),
        "method": row.get("method"),
        "template": row.get("template"),
        "obj_id": row.get("obj_id"),
        "status": row.get("status"),
        "query": list(row.get("query") or ()),
        "signal": sorted(row.get("signal") or ()),
    }


def feature_rows(events, baselines) -> list[dict]:
    """The event as a rule sees it, which is the only view the proposer gets."""
    return [dsl.features(event, baselines) for event in events]


def load_variants(path: Path | None = None) -> list[dict]:
    target = Path(path) if path is not None else paths.data_dir() / "variants.json"
    if not target.exists():
        raise FileNotFoundError(
            f"{target} is missing. Build it with "
            f"`python -m minny.redteam.generate --seed 42 --count 200`."
        )
    return json.loads(target.read_text(encoding="utf-8"))


def training_variants(
    variants: list[dict],
    *,
    operator: str,
    personas: tuple[str, ...] = TRAINING_PERSONAS,
) -> list[dict]:
    """Every variant carrying the operator, from the training personas only."""
    return [
        variant
        for variant in variants
        if operator in variant["operators"] and variant["persona"] in personas
    ]


def sample(events: list, size: int = BENIGN_SAMPLE) -> list:
    """A strided sample, not a slice.

    The first 6,000 events of March are the first eight days of it. A stride
    keeps the whole month's shape, weekends included, which is where a
    threshold written against weekday traffic goes wrong.
    """
    if size >= len(events):
        return list(events)
    stride = max(1, len(events) // size)
    return events[::stride][:size]


def incident_rows(frame, baselines) -> list[dict]:
    """The 26 labeled lines of the real March breach, as features."""
    labeled = frame[frame["line"].isin(sorted(INCIDENT_LINES))]
    return feature_rows(from_frame(labeled), baselines)


def suppression_row(metrics: dict | None, operator: str) -> dict | None:
    """What the evaluation measured this operator switching off, if anything.

    The blue agent is pointed at an operator by a number somebody else
    produced. Reading it out of metrics.json rather than restating it here
    means the claim in a proposal always matches the claim on the metrics
    panel.
    """
    if not metrics:
        return None
    rows = [
        row
        for row in metrics.get("signal_suppression", [])
        if row.get("operator") == operator
    ]
    if not rows:
        return None
    return max(rows, key=lambda row: row.get("suppression", 0))


def load_metrics(path: Path | None = None) -> dict | None:
    target = Path(path) if path is not None else paths.metrics_path()
    if not target.exists():
        return None
    return json.loads(target.read_text(encoding="utf-8"))


def build(
    *,
    operator: str,
    variants: list[dict],
    benign: list,
    frame,
    baselines,
    metrics: dict | None = None,
    personas: tuple[str, ...] = TRAINING_PERSONAS,
) -> Evidence:
    """Assemble the packet for one evaded operator."""
    training = training_variants(variants, operator=operator, personas=personas)
    if not training:
        raise ValueError(
            f"no {operator} variants from personas {', '.join(personas)}; "
            f"there is nothing to propose a rule from"
        )
    row = suppression_row(metrics, operator)
    benign_sample = sample(benign)
    return Evidence(
        operator=operator,
        signal=(row or {}).get("signal"),
        signal_name=(row or {}).get("signal_name"),
        suppression=row,
        seeds=tuple(sorted({variant["seed"] for variant in training})),
        personas=tuple(personas),
        variants=tuple(training),
        variant_features=tuple(
            feature_rows([e for v in training for e in variant_events(v)], baselines)
        ),
        benign=tuple(benign_sample),
        benign_features=tuple(feature_rows(benign_sample, baselines)),
        incident_features=tuple(incident_rows(frame, baselines)),
    )
