"""Replay the held-out window through the detector.

    python -m minny.detect.run

Writes data/alerts.json and data/incidents.json, then prints the numbers the
watchdog is judged on: how many incidents March produces, who they name, and
how many alerts did not belong to one. That last figure is the credibility of
the whole system, so it is printed with every remaining alert listed
individually rather than summarised away.

The baseline window is replayed too, as a control. Signals fitted on it should
be silent across it; anything that fires there is a false positive by
construction and has to be explained before the March numbers mean anything.

This drives the same `Pipeline` the live stream drives, with the same rules
loaded from detection-rules/rules.yaml. Batch and streaming are one code path,
so a number printed here is the number the UI will show.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd

from minny import paths
from minny.baselines.model import Baselines
from minny.build_events import BASELINE_CUTOFF
from minny.detect.events import from_frame
from minny.detect.replay import Pipeline
from minny.detect.rules import RuleSet


def replay(frame: pd.DataFrame, baselines: Baselines, rules=None) -> tuple:
    pipeline = Pipeline(baselines, rules=rules)
    alerts, incidents = pipeline.run(from_frame(frame))
    return alerts, incidents, pipeline


def _window(frame: pd.DataFrame, start=None, end=None) -> pd.DataFrame:
    selected = frame
    if start is not None:
        selected = selected[selected["ts"] >= pd.Timestamp(start)]
    if end is not None:
        selected = selected[selected["ts"] < pd.Timestamp(end)]
    return selected


def _print_alerts(alerts: list, prefix: str = "  ") -> None:
    for alert in sorted(alerts, key=lambda a: (a["evidence_lines"][0], a["signal"])):
        print(
            f"{prefix}{alert['signal']} {alert['severity']:<6} "
            f"lines={alert['evidence_lines']} {alert['explanation']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", default=str(paths.events_path()))
    parser.add_argument("--baselines", default=str(paths.baselines_path()))
    parser.add_argument("--out-dir", default=str(paths.data_dir()))
    parser.add_argument(
        "--from",
        dest="start",
        default=None,
        help="ISO timestamp; defaults to the baseline cutoff, i.e. all of March",
    )
    parser.add_argument("--to", dest="end", default=None)
    parser.add_argument(
        "--skip-control",
        action="store_true",
        help="skip the baseline-window replay that validates the thresholds",
    )
    parser.add_argument(
        "--no-rules",
        action="store_true",
        help="ignore detection-rules/rules.yaml and run the built-in signals only",
    )
    args = parser.parse_args()

    frame = pd.read_parquet(paths.require(Path(args.events)))
    baselines = Baselines.load(Path(args.baselines))
    start = datetime.fromisoformat(args.start) if args.start else BASELINE_CUTOFF
    end = datetime.fromisoformat(args.end) if args.end else None

    rules = None if args.no_rules else RuleSet.load()
    if rules is not None:
        enabled = sum(1 for rule in rules.rules if rule.ok)
        print(
            f"rules       {enabled} of {len(rules.rules)} loaded from "
            f"{rules.path}, {len(rules.errors)} error(s)"
        )
        for failure in rules.errors:
            print(f"            {failure.get('id') or 'file'}: {failure['error']}")

    if not args.skip_control:
        control = _window(frame, end=BASELINE_CUTOFF)
        control_alerts, control_incidents, _ = replay(control, baselines, rules)
        print(
            f"control     {len(control):,} baseline-window events -> "
            f"{len(control_alerts)} alerts, {len(control_incidents)} incidents"
        )
        if control_alerts:
            print("            these are false positives by construction:")
            _print_alerts(control_alerts, prefix="            ")
        else:
            print("            S3 at 3-in-30s produces 0 baseline-window hits")

    held_out = _window(frame, start=start, end=end)
    if held_out.empty:
        print(f"replayed    0 events from {start.isoformat()}; nothing to do")
        return
    if rules is not None:
        # The control replay left its rolling history behind it. The held-out
        # window is a separate run and must not count events from the fitted
        # one towards a rule's window.
        rules.reset()
    alerts, incidents, pipeline = replay(held_out, baselines, rules)

    print(
        f"replayed    {len(held_out):,} events from {start.isoformat()} "
        f"to {(end or held_out['ts'].max()).isoformat()}"
    )
    counts = Counter(a["signal"] for a in alerts)
    print(
        f"alerts      {len(alerts)} "
        f"({', '.join(f'{k}={counts[k]}' for k in sorted(counts))})"
    )
    print(
        f"authorship  {len(pipeline.detector.state.authorships)} S7 links "
        f"(no alerts emitted)"
    )
    print(f"incidents   {len(incidents)}")
    for incident in incidents:
        attacker = incident["attacker"]
        victim = incident["victim"]
        print(
            f"  {incident['incident_id']}  {incident['severity']:<6} "
            f"attacker={attacker['user']}({attacker['confidence']}) "
            f"victim={victim['user']}({victim['confidence']}) "
            f"alerts={len(incident['alerts'])}"
        )
        print(f"    {incident['title']}")

    claimed = {aid for inc in incidents for aid in inc["alerts"]}
    loose = [a for a in alerts if a["alert_id"] not in claimed]
    print(f"non-incident alerts on the replayed window: {len(loose)}")
    if loose:
        # Never summarised. Each one is either a real finding or a defect, and
        # the only honest way to hand the number over is with the list.
        _print_alerts(loose, prefix="  ")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "alerts.json").write_text(
        json.dumps(alerts, indent=2), encoding="utf-8"
    )
    (out_dir / "incidents.json").write_text(
        json.dumps(incidents, indent=2), encoding="utf-8"
    )
    print(f"wrote       {out_dir / 'alerts.json'}")
    print(f"wrote       {out_dir / 'incidents.json'}")


if __name__ == "__main__":
    main()
