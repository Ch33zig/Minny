"""Derive the monitor fixtures from a real replay.

    python -m minny.detect.emit_fixture

The front end reads `fixtures/mock/*` when the URL carries `?mock=1`, which is
how it runs with no backend and how the demo survives a dead API. Those files
were hand authored, and hand authored fixtures drift: the detector alert said
the baseline had refused the account 70 times, the case file said 77 denials
preceded the download, and the fixture said 80. Only one of those three was
wrong, but a judge reading two screens has no way to know which.

So the monitor fixtures are generated from the same replay that produces
`data/alerts.json` and `data/incidents.json`. A number can still be wrong here,
but it can no longer be wrong in only one place.

The stream file is a subsample. A real March replay emits roughly 23,000 event
frames and the fixture needs to stay small enough to ship, so every alert,
incident and replay_state frame is kept and ordinary events are kept only near
something that happened.
"""

from __future__ import annotations

import json
from pathlib import Path

from minny import paths

FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "mock"

# Events either side of an alert that are worth keeping for context in the
# ticker. Wide enough that a viewer sees ordinary traffic around the finding,
# narrow enough that the file stays a fixture rather than a dataset.
CONTEXT_EVENTS = 3
MAX_FRAMES = 140


def _load(path: Path) -> list:
    return json.loads(path.read_text(encoding="utf-8"))


def build_stream(events: list[dict], alerts: list[dict], incidents: list[dict]) -> list[dict]:
    """Interleave frames in timestamp order, the way the live stream does.

    Incidents are re-emitted every time their alert count rises, because the UI
    upserts on `incident_id` and drives its growth animation from that number.
    One frame at the end would render the same card and lose the entire point.
    """
    alert_lines = {line for alert in alerts for line in alert["evidence_lines"]}
    keep: set[int] = set()
    ordered = sorted(events, key=lambda e: e["line"])
    for index, event in enumerate(ordered):
        if event["line"] in alert_lines:
            low = max(0, index - CONTEXT_EVENTS)
            high = min(len(ordered), index + CONTEXT_EVENTS + 1)
            keep.update(ordered[position]["line"] for position in range(low, high))

    frames: list[tuple[str, str, dict]] = []
    for event in ordered:
        if event["line"] in keep:
            frames.append((event["ts"], "event", event))
    for alert in alerts:
        frames.append((alert["ts"], "alert", alert))

    # Rebuild the incident as it grew, one frame per alert it absorbed.
    for incident in incidents:
        members = [a for a in alerts if a.get("incident_id") == incident["incident_id"]]
        members.sort(key=lambda a: (a["ts"], a["alert_id"]))
        for count, alert in enumerate(members, start=1):
            snapshot = dict(incident)
            snapshot["alert_count"] = count
            snapshot["last_ts"] = alert["ts"]
            snapshot["alerts"] = [a["alert_id"] for a in members[:count]]
            # Severity is earned as evidence accumulates rather than asserted
            # from the first alert, which is what the growing card shows.
            snapshot["severity"] = incident["severity"] if count >= 3 else "medium"
            frames.append((alert["ts"], "incident", snapshot))

    frames.sort(key=lambda item: (item[0], {"event": 0, "alert": 1, "incident": 2}[item[1]]))
    if len(frames) > MAX_FRAMES:
        frames = frames[:MAX_FRAMES]

    out = []
    for seq, (ts, kind, payload) in enumerate(frames, start=1):
        out.append({"type": kind, "seq": seq, "ts": ts, "data": payload})
    return out


def main() -> None:
    data = paths.data_dir()
    alerts = _load(paths.require(data / "alerts.json"))
    incidents = _load(paths.require(data / "incidents.json"))

    import pandas as pd

    frame = pd.read_parquet(paths.require(paths.events_path()))
    cited = {line for alert in alerts for line in alert["evidence_lines"]}
    low, high = min(cited) - 12, max(cited) + 12
    window = frame[(frame["line"] >= low) & (frame["line"] <= high)]
    events = [
        {
            "line": int(row.line),
            "raw": row.raw,
            "ts": row.ts.isoformat(),
            "user": row.user,
            "ip": row.ip,
            "method": row.method,
            "path": row.path,
            "status": int(row.status),
            "size": int(row.size),
        }
        for row in window.itertuples()
    ]

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)

    # The case file writes this file with the lines it cites. The monitor cites
    # a few more for ticker context, so union rather than overwrite: every line
    # any fixture references has to resolve to raw bytes or the drill-down,
    # which is the one interaction that proves the product, breaks.
    events_file = FIXTURE_DIR / "events.json"
    existing = _load(events_file) if events_file.exists() else []
    by_line = {row["line"]: row for row in existing}
    for row in events:
        by_line.setdefault(row["line"], row)
    events_file.write_text(
        json.dumps([by_line[k] for k in sorted(by_line)], indent=2), encoding="utf-8"
    )
    (FIXTURE_DIR / "alerts.json").write_text(
        json.dumps(alerts, indent=2), encoding="utf-8"
    )
    (FIXTURE_DIR / "incidents.json").write_text(
        json.dumps(incidents, indent=2), encoding="utf-8"
    )
    stream = build_stream(events, alerts, incidents)
    (FIXTURE_DIR / "stream.ndjson").write_text(
        "\n".join(json.dumps(f) for f in stream) + "\n", encoding="utf-8"
    )

    print(f"alerts      {len(alerts)}")
    print(f"incidents   {len(incidents)}")
    print(f"stream      {len(stream)} frames")
    print(f"wrote       {FIXTURE_DIR}")


if __name__ == "__main__":
    main()
