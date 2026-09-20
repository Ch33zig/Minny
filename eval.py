"""The evaluation harness (milestone M5).

    python eval.py --seed 42

Writes data/metrics.json to 00-CONTRACTS.md section 9 and prints the
per-operator table. Everything this project says on stage comes out of this
command, which is the only reason anyone should believe it.

What it does, in order:

1. Loads the 200 labeled variants for the seed, regenerating them in process
   if the file on disk was built from a different one.
2. Replays the benign stream, March minus the 26 labeled incident lines, and
   counts what fires on it. Those are the false positives.
3. Replays March intact and scores the real 13-15 March breach.
4. Injects each variant into the benign stream **on its own**, with a fresh
   detector and correlator, and scores detection, attribution and time to
   detect.

The harness contains no detection logic. It builds the same `Detector` and
`Correlator` the live system builds and feeds them through the same
`minny.detect.events.merged` hook the replay engine uses, so when a signal
changes this file does not and the numbers move by themselves.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from minny import paths
from minny.baselines.model import Baselines
from minny.eval import harness, metrics as metrics_module, report, stream
from minny.redteam.catalog import INCIDENT_LINES


def load_variants(path: Path, *, seed: int, count: int, regenerate: bool) -> list[dict]:
    """Prefer the file on disk, but never score a set from another seed.

    Generation is deterministic and takes about two seconds, so silently
    regenerating is cheaper than a metrics.json whose `seed` field and whose
    variants disagree. That mismatch is invisible in the output and fatal to
    every claim made from it.
    """
    on_disk = None
    if path.exists() and not regenerate:
        on_disk = json.loads(path.read_text(encoding="utf-8"))
    if on_disk and all(v.get("seed") == seed for v in on_disk) and len(on_disk) >= count:
        return on_disk[:count]

    from minny.redteam.generate import generate

    reason = "regenerating" if regenerate else f"no seed-{seed} set on disk"
    print(f"variants    {reason}, running the generator in process")
    accepted, _rejected = generate(seed=seed, count=count)
    return accepted


def _wallclock(events: int, seconds: float) -> dict:
    """Detector time only, summed over every replay the command performed.

    Parquet loading and stream merging are harness overhead. Folding them into
    a per-event latency would flatter the detector by a factor nobody outside
    this file could reproduce.
    """
    return {
        "events": events,
        "seconds": round(seconds, 3),
        "ms_per_event": round(seconds * 1000 / events, 4) if events else 0.0,
    }


def run(*, seed: int, count: int, variants_path: Path, regenerate: bool) -> dict:
    baselines = Baselines.load(paths.require(paths.baselines_path()))
    variants = load_variants(
        variants_path, seed=seed, count=count, regenerate=regenerate
    )

    frame = stream.march_frame()
    benign = stream.benign_events(frame)
    march = stream.march_events(frame)
    days = stream.days_covered(benign)
    print(
        f"streams     {len(march):,} March events, {len(benign):,} benign "
        f"after removing {len(INCIDENT_LINES)} labeled incident lines, "
        f"{len(days)} days"
    )

    benign_replay = harness.replay(iter(benign), baselines)
    print(
        f"benign      {len(benign_replay.alerts)} alerts, "
        f"{len(benign_replay.incidents)} incidents"
    )

    march_replay = harness.replay(iter(march), baselines)
    real = metrics_module.real_incident_result(
        march_replay.alerts, march_replay.incidents, INCIDENT_LINES
    )
    print(
        f"real        {'detected' if real['detected'] else 'MISSED'}, "
        f"attacker={real['named_attacker']} victim={real['named_victim']}, "
        f"{real['alert_count']} alerts"
    )

    outcomes: list[harness.Outcome] = []
    for index, variant in enumerate(variants, start=1):
        outcomes.append(harness.evaluate_variant(variant, benign, baselines))
        if index % 50 == 0 or index == len(variants):
            caught = sum(1 for o in outcomes if o.detected)
            print(f"variants    {index}/{len(variants)} replayed, {caught} detected")

    wallclock = _wallclock(
        benign_replay.events
        + march_replay.events
        + sum(o.events for o in outcomes),
        benign_replay.seconds
        + march_replay.seconds
        + sum(o.seconds for o in outcomes),
    )

    return metrics_module.build(
        seed=seed,
        outcomes=outcomes,
        benign_alerts=benign_replay.alerts,
        benign_incidents=benign_replay.incidents,
        benign_days=days,
        wallclock=wallclock,
        real_incident=real,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--variants", default=None, help="defaults to the data dir")
    parser.add_argument("--out", default=None, help="defaults to data/metrics.json")
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="rebuild the variant set from the seed instead of reading it",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="print the report without touching metrics.json",
    )
    args = parser.parse_args(argv)

    variants_path = (
        Path(args.variants) if args.variants else paths.data_dir() / "variants.json"
    )
    metrics = run(
        seed=args.seed,
        count=args.count,
        variants_path=variants_path,
        regenerate=args.regenerate,
    )

    print()
    print(report.render(metrics))

    if not args.no_write:
        out_path = Path(args.out) if args.out else paths.metrics_path()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        print()
        print(f"wrote       {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
