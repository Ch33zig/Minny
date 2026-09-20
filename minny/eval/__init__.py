"""The evaluation harness (milestone M5).

One command, `python eval.py --seed 42`, produces every number the project
says out loud. The pieces are split so each one can be tested on its own:
`stream` decides what is replayed, `harness` replays it and scores it,
`metrics` turns outcomes into the contract's file, and `report` prints the
table a person reads at 02:30.
"""

from minny.eval.harness import Outcome, Replay, evaluate_all, evaluate_variant, replay
from minny.eval.metrics import build, real_incident_result
from minny.eval.stream import (
    BENIGN_STREAM_LABEL,
    benign_events,
    days_covered,
    march_events,
    march_frame,
    variant_events,
)

__all__ = [
    "BENIGN_STREAM_LABEL",
    "Outcome",
    "Replay",
    "benign_events",
    "build",
    "days_covered",
    "evaluate_all",
    "evaluate_variant",
    "march_events",
    "march_frame",
    "real_incident_result",
    "replay",
    "variant_events",
]
