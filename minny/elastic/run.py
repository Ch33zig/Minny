"""Build every Elastic artifact, offline or against a live cluster.

    python -m minny.elastic.run

With no environment set this writes the mappings, the exact `_bulk` NDJSON
for the events and the alerts, the translated ES|QL for every rule, and the
fidelity report that compares the translation against the Python rule walker.
With `ELASTICSEARCH_URL` and `ELASTIC_INGEST_API_KEY` set it creates the
indices and sends the same bytes instead, and the same completeness barrier
runs against the cluster's own count.

Nothing here can fail a caller. Each stage reports `ok` and the run continues
to the next one, because the fidelity report is worth having even on a day
the cluster is unreachable, and the NDJSON is worth having even on a day the
alerts file has not been built yet.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

from minny import paths
from minny.elastic import documents, esql, executor, fidelity, mapping
from minny.elastic.bulk import index_pairs
from minny.elastic.client import ElasticClient

SAMPLE_ROWS = 5
PROBE_DOCUMENTS = 3


def _read_json(path: Path, default):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def _file_sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def load_events(limit: int | None = None):
    """The parsed corpus, in replay order, as DetectEvent objects."""
    import pandas as pd

    from minny.detect.events import from_frame

    frame = pd.read_parquet(paths.events_path())
    if limit:
        frame = frame.head(limit)
    return list(from_frame(frame)), len(frame)


def bootstrap(client: ElasticClient, out_dir: Path) -> dict:
    """Create the indices, or write the mappings where they can be read."""
    mappings_dir = out_dir / "mappings"
    mappings_dir.mkdir(parents=True, exist_ok=True)
    results = {}
    for kind, name in client.indices.items():
        body = mapping.MAPPINGS[kind]()
        (mappings_dir / f"{name}.json").write_text(
            json.dumps(body, indent=2) + "\n", encoding="utf-8"
        )
        if client.configured:
            results[kind] = client.create_index(name, body)
        else:
            results[kind] = {
                "ok": True,
                "created": False,
                "name": name,
                "written": str(mappings_dir / f"{name}.json"),
            }
    return results


def event_pairs(events, *, workspace_id, baselines, signals, event_set_sha256):
    for event in events:
        fired = signals.get(int(event.line), ())
        document = documents.event_document(
            event,
            workspace_id=workspace_id,
            ip_owner=baselines.owner_of(event.ip) if baselines else None,
            signals=fired,
            event_set_sha256=event_set_sha256,
        )
        yield documents.doc_id(
            workspace_id, "events", documents.event_identity(event)
        ), document


def alert_pairs(alerts, *, workspace_id, event_set_sha256):
    for alert in alerts:
        document = documents.alert_document(
            alert, workspace_id=workspace_id, event_set_sha256=event_set_sha256
        )
        yield documents.doc_id(
            workspace_id, "alerts", documents.alert_identity(alert)
        ), document


def rule_expressions() -> list:
    """Every rule in detection-rules/rules.yaml, in file order."""
    from minny.detect.rules import RuleSet

    ruleset = RuleSet.load()
    return [
        {"id": rule.id, "when": rule.when, "note": rule.name}
        for rule in ruleset.rules
    ], ruleset


def _verify_null_corpus(index: str, workspace_id: str) -> list:
    """The same comparison over events chosen to contain every null case."""
    events, owners, signals = fidelity.null_corpus()
    probes = [
        {"id": f"null_{position:02d}", "when": source, "note": note}
        for position, (source, note) in enumerate(fidelity.NULL_PROBES, start=1)
    ]
    prepared = fidelity.prepare(probes, index=index)
    results = fidelity.compare(
        prepared,
        events,
        owners,
        signals=signals,
        workspace_id=workspace_id,
        sample=SAMPLE_ROWS,
    )
    for row in results:
        row.pop("documents", None)
    return results


def translate_and_verify(
    events, baselines, alerts, *, client: ElasticClient, out_dir: Path
) -> dict:
    """Translate every rule and probe, then prove the translations."""
    index = client.indices["events"]
    rules, ruleset = rule_expressions()
    probes = [
        {"id": f"probe_{position:02d}", "when": source, "note": note}
        for position, (source, note) in enumerate(fidelity.PROBES, start=1)
    ]

    prepared = fidelity.prepare(rules + probes, index=index)
    signals = fidelity.signal_index(alerts)
    results = fidelity.compare(
        prepared,
        events,
        baselines,
        signals=signals,
        workspace_id=client.workspace_id,
        sample=SAMPLE_ROWS,
        keep_documents=PROBE_DOCUMENTS,
    )

    rule_ids = {entry["id"] for entry in rules}
    esql_dir = out_dir / "esql"
    esql_dir.mkdir(parents=True, exist_ok=True)

    written = []
    for row in results:
        if row["id"] not in rule_ids or not row["query"]:
            continue
        path = esql_dir / f"{row['id']}.esql"
        header = "\n".join(
            f"// {line}"
            for line in (
                f"rule {row['id']}: {row['note']}",
                f"when: {row['when']}",
                f"fidelity: {row['fidelity']} ({row['reason']})",
                f"verified: {row['verdict']} - {row['detail']}",
                "generated by minny.elastic.esql from the rule predicate; the",
                "predicate is canonical and this file is derived, never the",
                "other way round",
            )
        )
        path.write_text(f"{header}\n{row['query']}\n", encoding="utf-8")
        written.append(path.name)

    # The shipped pipeline, stage for stage, over the documents it selected.
    # The WHERE comparison above proves the predicate; this proves the KEEP,
    # SORT and LIMIT stages parse and run as written.
    pipelines = []
    for row in results:
        if not row["query"] or not row["documents"]:
            continue
        try:
            executed = executor.run(row["query"], row["documents"])
        except executor.EsqlError as exc:
            pipelines.append({"id": row["id"], "ok": False, "error": str(exc)})
            continue
        pipelines.append(
            {
                "id": row["id"],
                "ok": True,
                "columns": executed["columns"],
                "rows": executed["values"][:SAMPLE_ROWS],
            }
        )

    for row in results:
        row.pop("documents", None)

    null_results = _verify_null_corpus(index, client.workspace_id)

    summary = fidelity.summarize(results)
    summary["null_corpus"] = fidelity.summarize(null_results)
    summary["passed"] = bool(
        summary["passed"] and summary["null_corpus"]["passed"]
    )
    payload = {
        "generated_ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "index": index,
        "mode": client.mode,
        "summary": summary,
        "null_corpus": {
            "why": (
                "the real access log has a user on every line and an owner "
                "for every address, so it cannot exercise the null handling "
                "a three-valued translation is most likely to get wrong"
            ),
            "events": len(fidelity.NULL_ROWS),
            "results": null_results,
        },
        "rules": [row for row in results if row["id"] in rule_ids],
        "probes": [row for row in results if row["id"] not in rule_ids],
        "pipelines": pipelines,
        "files": written,
        "rule_errors": list(ruleset.errors),
    }
    (esql_dir / "summary.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    return payload


def build(*, limit: int | None = None, skip_bulk: bool = False) -> dict:
    from minny.baselines.model import Baselines

    out_dir = paths.elastic_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    client = ElasticClient()

    report: dict = {
        "generated_ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "client": client.describe(),
        "ping": None,
        "bootstrap": None,
        "ingest": {},
        "esql": None,
    }

    if client.configured:
        report["ping"] = client.ping()

    report["bootstrap"] = bootstrap(client, out_dir)

    events, row_count = load_events(limit)
    event_set_sha256 = _file_sha256(paths.events_path())
    alerts = _read_json(paths.alerts_path(), [])
    if not isinstance(alerts, list):
        alerts = []
    baselines = None
    try:
        baselines = Baselines.load()
    except Exception as exc:  # noqa: BLE001 - ip_owner is optional context
        report["baselines_error"] = f"{type(exc).__name__}: {exc}"

    signals = fidelity.signal_index(alerts)

    if not skip_bulk:
        report["ingest"]["events"] = index_pairs(
            client,
            client.indices["events"],
            event_pairs(
                events,
                workspace_id=client.workspace_id,
                baselines=baselines,
                signals=signals,
                event_set_sha256=event_set_sha256,
            ),
            kind="events",
            out_dir=out_dir / "bulk",
            expected=row_count,
            refresh="wait_for" if client.configured else None,
        )
        report["ingest"]["alerts"] = index_pairs(
            client,
            client.indices["alerts"],
            alert_pairs(
                alerts,
                workspace_id=client.workspace_id,
                event_set_sha256=event_set_sha256,
            ),
            kind="alerts",
            out_dir=out_dir / "bulk",
            expected=len(alerts),
            refresh="wait_for" if client.configured else None,
        )

    report["esql"] = translate_and_verify(
        events, baselines, alerts, client=client, out_dir=out_dir
    )
    report["source"] = {
        "events_path": str(paths.events_path()),
        "events_sha256": event_set_sha256,
        "event_rows": row_count,
        "alert_rows": len(alerts),
    }

    status_path = out_dir / "status.json"
    status_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def _print(report: dict) -> None:
    client = report["client"]
    print(f"mode: {client['mode']}  workspace: {client['workspace_id']}")
    for kind, name in client["indices"].items():
        print(f"  {kind}: {name}")
    for kind, result in (report.get("ingest") or {}).items():
        flag = "complete" if result["complete"] else "INCOMPLETE"
        print(
            f"  {kind}: {result['accepted_count']}/{result['expected_count']} "
            f"documents in {result['batches']} batches, "
            f"{result['bytes'] / 1e6:.1f} MB, {flag} "
            f"(verified by {result['verification']['method']})"
        )
    summary = (report.get("esql") or {}).get("summary") or {}
    if summary:
        print(
            f"  esql: {summary['agreed']}/{summary['row_preserving']} "
            f"row-preserving expressions agree with the rule walker, "
            f"{summary['approximate']} approximate, "
            f"{summary['untranslated']} not translated"
        )
        nulls = summary.get("null_corpus") or {}
        if nulls:
            print(
                f"  null corpus: {nulls['agreed']}/{nulls['row_preserving']} "
                f"agree on events carrying every null case"
            )
    print(f"  artifacts: {paths.elastic_dir()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the Elastic artifacts")
    parser.add_argument(
        "--limit", type=int, default=None, help="only the first N events"
    )
    parser.add_argument(
        "--skip-bulk", action="store_true", help="translate and verify only"
    )
    args = parser.parse_args()
    report = build(limit=args.limit, skip_bulk=args.skip_bulk)
    _print(report)
    summary = (report.get("esql") or {}).get("summary") or {}
    if summary and not summary.get("passed"):
        sys.exit(1)


if __name__ == "__main__":
    main()
