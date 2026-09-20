"""The streams the evaluation replays (milestone M5).

There are three of them and keeping them apart is most of what makes the
numbers honest.

The **benign stream** is March minus the 26 labeled incident lines. False
positives are counted on it, so leaving the real attack in would count our own
success as noise and make the detector look twice as loud as it is.

A **variant stream** is one red-team variant, parsed back out of its rendered
text through `minny.parser` and handed to the detector through
`minny.detect.events`. Nothing here knows what a signal is: an injected event
reaches the detector by exactly the path a real one does, which is the only
way the per-operator table measures the detector rather than the harness.

The **real-incident stream** is March with those 26 lines back in place, which
is what `python -m minny.detect.run` replays. It is scored once and reported
on its own, because one incident is an anecdote and 200 variants are a
measurement.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from minny import paths
from minny.build_events import BASELINE_CUTOFF
from minny.detect.events import DetectEvent, from_frame, from_row
from minny.parser import parse_line
from minny.redteam.catalog import INCIDENT_LINES

# The string D's metrics panel prints under the false-positive tile. It is a
# definition, not a caption, so it lives next to the code that enforces it.
BENIGN_STREAM_LABEL = "March 2026 minus labeled incident lines"


def march_frame(events_path: Path | None = None) -> pd.DataFrame:
    """Every held-out event, incident lines included.

    Compared as an aware timestamp against the log's own fixed offset. A naive
    cutoff would move the boundary by four hours and silently pull the last of
    February into the measured window.
    """
    path = Path(events_path) if events_path else paths.events_path()
    frame = pd.read_parquet(paths.require(path))
    return frame[frame["ts"] >= pd.Timestamp(BASELINE_CUTOFF)]


def benign_events(frame: pd.DataFrame) -> list[DetectEvent]:
    """March with the real incident removed. The false-positive denominator."""
    kept = frame[~frame["line"].isin(sorted(INCIDENT_LINES))]
    return list(from_frame(kept))


def march_events(frame: pd.DataFrame) -> list[DetectEvent]:
    """March exactly as it happened, for scoring the real incident."""
    return list(from_frame(frame))


def variant_events(variant: dict) -> list[DetectEvent]:
    """One variant's rendered lines, read back through the real parser.

    Round-tripping through the text rather than carrying a structured copy is
    deliberate: if the renderer ever emits something the parser cannot read,
    the evaluation fails here rather than quietly scoring a variant the live
    system could never have ingested.
    """
    lines = variant.get("lines")
    if not lines:
        raise ValueError(
            f"{variant.get('variant_id', 'variant')} carries no rendered lines. "
            "Regenerate with `python -m minny.redteam.generate --seed 42`."
        )
    return [from_row(parse_line(line["line"], line["raw"])) for line in lines]


def days_covered(events: list[DetectEvent]) -> list[str]:
    """Every calendar day the stream touches, in the log's own offset.

    Zero-filled days matter: a per-day false-positive rate divided by the days
    that happened to alert is not a rate, it is a tautology.
    """
    return sorted({event.ts.date().isoformat() for event in events})
