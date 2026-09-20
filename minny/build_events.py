"""Build the canonical artifacts every other track reads (milestone M0).

    python -m minny.build_events

Writes data/events.parquet, data/size_table.json and data/access_matrix.json
to the shapes in docs/handoff/00-CONTRACTS.md sections 1 to 3.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from minny import paths
from minny.parser import EXPECTED_ROWS, Event, parse_file

# Every one of the 180,800 lines carries -0400, including March dates that
# would be EST in a real US/Eastern log. The log keeps a fixed offset, so we
# store a fixed offset. Converting to a named zone would re-interpret the
# pre-8-March lines and print a wall clock an hour off the raw evidence line
# sitting next to it in the UI.
LOG_TZ = timezone(timedelta(hours=-4))

# March 2026 is held out. Every baseline-style artifact fits below this line
# so the 13-15 March incident can never train the thing meant to catch it.
# Compared as an aware datetime, never as a string.
BASELINE_CUTOFF = datetime(2026, 3, 1, tzinfo=LOG_TZ)
SENSITIVE_MARKERS = ("CONFIDENTIAL", "/finance/", "/hr/", "/exec/", "/it/scripts/")


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def to_dataframe(events: list[Event]) -> pd.DataFrame:
    frame = pd.DataFrame(
        {
            "line": pd.array([e.line for e in events], dtype="int32"),
            "raw": [e.raw for e in events],
            "ip": [e.ip for e in events],
            "user": [e.user for e in events],
            "ts": [e.ts for e in events],
            "method": [e.method for e in events],
            "path": [e.path for e in events],
            "base": [e.base for e in events],
            "query": [e.query for e in events],
            "status": pd.array([e.status for e in events], dtype="int16"),
            "size": pd.array([e.size for e in events], dtype="int64"),
            "template": [e.template for e in events],
            "obj_id": pd.array([e.obj_id for e in events], dtype="Int64"),
        }
    )
    # Timezone awareness is not cosmetic: the correlator windows on this column
    # and a naive value silently shifts every window by four hours. The offset
    # is the log's own fixed -0400 so that ts always agrees with the raw line.
    frame["ts"] = pd.to_datetime(frame["ts"], utc=True).dt.tz_convert(LOG_TZ)
    return frame


def build_size_table(events: list[Event], source_sha: str) -> dict:
    """Record the response size for every (base, status) pair that has one.

    This is the realism constraint for the red team. A synthetic line carrying
    a size that never occurs in the real data is detectable by inspection, and
    the whole stress test becomes theatre.
    """
    observed: dict[tuple[str, int], set[int]] = defaultdict(set)
    for event in events:
        observed[(event.base, event.status)].add(event.size)

    by_path: dict[str, dict[str, int]] = defaultdict(dict)
    variable: dict[str, dict[str, list[int]]] = defaultdict(dict)
    for (base, status), sizes in sorted(observed.items()):
        if len(sizes) == 1:
            by_path[base][str(status)] = next(iter(sizes))
        else:
            ordered = sorted(sizes)
            variable[base][str(status)] = [
                ordered[0],
                ordered[len(ordered) // 2],
                ordered[-1],
            ]

    by_status: dict[str, int] = {}
    for status in {e.status for e in events}:
        sizes = {e.size for e in events if e.status == status}
        if len(sizes) == 1:
            by_status[str(status)] = next(iter(sizes))

    return {
        "generated_from": "data/logs.txt",
        "sha256": source_sha,
        "by_status": dict(sorted(by_status.items())),
        "by_path": {k: dict(sorted(v.items())) for k, v in sorted(by_path.items())},
        # C must sample a real observed size for these rather than inventing
        # one. Values are [min, median, max] of what actually occurs.
        "variable_size_paths": {
            k: dict(sorted(v.items())) for k, v in sorted(variable.items())
        },
    }


def build_access_matrix(
    events: list[Event], cutoff: datetime = BASELINE_CUTOFF
) -> dict:
    """Who is allowed to read what, derived rather than assumed.

    Fitted on the baseline window only. This is not a detail: the attacker
    succeeds exactly once on the confidential zip, and counting March would
    enrol him as an authorised reader of the file he stole, erasing the
    finding and handing C an incoherent access model.

    C needs this for victim_swap and target_swap, because a variant whose
    victim was never authorised is incoherent and the critic has to reject it.
    """
    successes: dict[str, set[str]] = defaultdict(set)
    denials: dict[str, set[str]] = defaultdict(set)
    sizes: dict[str, int] = {}

    for event in events:
        if not any(marker in event.base for marker in SENSITIVE_MARKERS):
            continue
        if event.user is None:
            continue
        if event.ts >= cutoff:
            continue
        if event.status == 200:
            successes[event.base].add(event.user)
            sizes[event.base] = event.size
        elif event.status == 403:
            denials[event.base].add(event.user)

    paths = {}
    for base in sorted(set(successes) | set(denials)):
        authorized = successes.get(base, set())
        paths[base] = {
            "size": sizes.get(base),
            "authorized": sorted(authorized),
            # Denied means denied and never succeeded. A user who was denied
            # once and later succeeded is the finding, not the baseline.
            "denied": sorted(denials.get(base, set()) - authorized),
            "confidential": "CONFIDENTIAL" in base,
        }

    return {"fit": {"cutoff": cutoff.isoformat()}, "paths": paths}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs", default=str(paths.logs_path()))
    parser.add_argument("--out", default=str(paths.data_dir()))
    args = parser.parse_args()

    logs_path = Path(args.logs)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    source_sha = sha256_of(logs_path)
    print(f"source      {logs_path}")
    print(f"sha256      {source_sha}")

    events = parse_file(logs_path)
    if len(events) != EXPECTED_ROWS:
        raise AssertionError(
            f"expected {EXPECTED_ROWS} rows, parsed {len(events)}. "
            "Stop and confirm the dataset before anyone builds on this."
        )
    print(f"parsed      {len(events):,} events, 0 unparsed")

    frame = to_dataframe(events)
    events_path = out_dir / "events.parquet"
    frame.to_parquet(events_path, index=False, compression="zstd")
    print(f"wrote       {events_path} ({events_path.stat().st_size / 1e6:.1f} MB)")

    size_table = build_size_table(events, source_sha)
    (out_dir / "size_table.json").write_text(
        json.dumps(size_table, indent=2), encoding="utf-8"
    )
    print(
        f"wrote       {out_dir / 'size_table.json'} "
        f"({len(size_table['by_path'])} fixed-size paths, "
        f"{len(size_table['variable_size_paths'])} variable)"
    )

    access = build_access_matrix(events)
    (out_dir / "access_matrix.json").write_text(
        json.dumps(access, indent=2), encoding="utf-8"
    )
    confidential = sum(1 for v in access["paths"].values() if v["confidential"])
    print(
        f"wrote       {out_dir / 'access_matrix.json'} "
        f"({len(access['paths'])} sensitive paths, {confidential} confidential)"
    )


if __name__ == "__main__":
    main()
