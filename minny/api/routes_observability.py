"""Elastic and Sentry status routes, mounted under /api by minny.api.app.

Routes are declared without the /api prefix because the application adds it.
Declaring it here too would serve them at /api/api and nobody would notice
until the UI was already wired up.

Three read-only endpoints, and every one of them is honest about which mode
produced its numbers. There is no Elastic deployment and no Sentry project
behind this repository, so `/elastic/status` says `offline` rather than
implying a cluster, and `/observability/status` reports zero events sent
along with the reason. When the credentials are present the same routes
report the live cluster and the live project through the same code.

Nothing here can fail. A missing artifact is a 503 naming the command that
builds it, an unreachable cluster is reported as unreachable, and a broken
file is an error field rather than a stack trace, because a status route
that falls over is worse than no status route.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from minny import observability as obs
from minny import paths
from minny.elastic import esql
from minny.elastic.client import ElasticClient

router = APIRouter(tags=["observability"])

BUILD_COMMAND = "python -m minny.elastic.run"

_cache: dict = {}


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status, content={"error": {"code": code, "message": message}}
    )


def _load(path: Path):
    """Read a JSON artifact, reusing the parse until the file changes."""
    key = str(path)
    try:
        info = path.stat()
        stamp = (info.st_mtime_ns, info.st_size)
    except OSError:
        _cache.pop(key, None)
        return None
    cached = _cache.get(key)
    if cached and cached[0] == stamp:
        return cached[1]
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    _cache[key] = (stamp, payload)
    return payload


def _missing(what: str) -> JSONResponse:
    return _error(
        503,
        "artifact_missing",
        f"{what} has not been built. Run `{BUILD_COMMAND}`. If you are in a "
        f"worktree, set MINNY_DATA_DIR to the main checkout's data directory.",
    )


@router.get("/elastic/status")
def elastic_status():
    """Connected or offline, the index names, and the document counts.

    The counts come from the last build rather than being recomputed per
    request: reading 180,800 rows to answer a status call would make the
    status call the slowest thing in the application. Online, the connection
    is checked live, because whether the cluster is reachable right now is
    exactly the question being asked.
    """
    client = ElasticClient()
    report = _load(paths.elastic_dir() / "status.json")

    payload = {
        "mode": client.mode,
        "connected": False,
        "reason": None,
        "workspace_id": client.workspace_id,
        "indices": dict(client.indices),
        "credentials": {
            "url_variable": "ELASTICSEARCH_URL",
            "key_variable": "ELASTIC_INGEST_API_KEY",
            "url_present": bool(client.url),
            "key_present": bool(client.api_key),
        },
        "documents": {},
        "last_build": None,
        "offline_artifacts": str(paths.elastic_dir()),
    }

    if client.configured:
        ping = client.ping()
        payload["connected"] = bool(ping.get("ok"))
        payload["cluster_name"] = ping.get("cluster_name")
        payload["version"] = ping.get("version")
        if not ping.get("ok"):
            payload["reason"] = ping.get("error")
    else:
        payload["reason"] = (
            "no deployment and no credentials on this machine; the bulk "
            "payload, the mappings and the translated ES|QL are built and "
            "written to disk instead of being sent"
        )

    if not report or report.get("error"):
        payload["documents"] = {}
        payload["last_build"] = (report or {}).get("error") or "never"
        return payload

    payload["last_build"] = report.get("generated_ts")
    for kind, result in (report.get("ingest") or {}).items():
        payload["documents"][kind] = {
            "index": result.get("index"),
            "expected": result.get("expected_count"),
            "indexed": result.get("accepted_count"),
            "failed": result.get("failed_count"),
            "batches": result.get("batches"),
            "bytes": result.get("bytes"),
            "complete": result.get("complete"),
            "verified_by": (result.get("verification") or {}).get("method"),
            "retrieved": (result.get("verification") or {}).get("retrieved_count"),
        }
    payload["source"] = report.get("source")
    return payload


@router.get("/elastic/rules")
def elastic_rules():
    """The translated ES|QL per rule, with the fidelity check result.

    `fidelity` is the claim and `verdict` is the evidence. `exact` plus
    `agree` means the translated query selected the same event ids the Python
    rule walker matched, over the whole corpus. `approximate` means the rule
    uses a sliding count that the v1 ES|QL command set cannot express, and
    the reason says so rather than the number being quietly rounded off.
    """
    report = _load(paths.elastic_dir() / "esql" / "summary.json")
    if not report:
        return _missing("the ES|QL summary")
    if report.get("error"):
        return _error(503, "artifact_unreadable", report["error"])

    def row(entry: dict) -> dict:
        return {
            "id": entry.get("id"),
            "name": entry.get("note"),
            "when": entry.get("when"),
            "esql": entry.get("query"),
            "fidelity": entry.get("fidelity"),
            "reason": entry.get("reason"),
            "verdict": entry.get("verdict"),
            "detail": entry.get("detail"),
            "agreed": entry.get("agreed"),
            "events_scanned": entry.get("events_scanned"),
            "rule_matches": entry.get("python_matches"),
            "esql_matches": entry.get("esql_matches"),
            "disagreements": {
                "only_rule_walker": entry.get("only_python"),
                "only_esql": entry.get("only_esql"),
            },
            "limit": entry.get("limit"),
            "limit_truncates": entry.get("limit_truncates"),
        }

    return {
        "generated_ts": report.get("generated_ts"),
        "index": report.get("index"),
        "mode": report.get("mode"),
        "summary": report.get("summary"),
        "rules": [row(entry) for entry in report.get("rules") or []],
        "probes": [row(entry) for entry in report.get("probes") or []],
        "edge_corpus": [
            row(entry)
            for entry in (report.get("null_corpus") or {}).get("results") or []
        ],
        "edge_corpus_why": (report.get("null_corpus") or {}).get("why"),
        "pipelines": report.get("pipelines"),
        "how_verified": (
            "each rule is evaluated by the Python rule walker over the real "
            "events and by a three-valued local executor running the "
            "generated query over the same documents the bulk indexer would "
            "ship; the two matched-line sets are compared for equality. This "
            "covers boolean structure, operator meaning and null handling. "
            "It does not stand in for a live cluster: index-time analysis, "
            "the ip field type and partial results under shard failure are "
            "unmodelled and need a deployment"
        ),
        "grammar": {
            "fields": sorted(esql.COLUMNS),
            "columns": dict(esql.COLUMNS),
        },
    }


@router.get("/observability/status")
def observability_status():
    """Sentry enabled or offline, span counts, and the scrubbing in force.

    `events_sent_without_dsn` is a constant zero and it is in the payload on
    purpose: the claim that nothing is transmitted without a DSN is the one
    a reader should be able to check rather than take.
    """
    status = obs.status()
    offline = _load(paths.sentry_dir() / "spans.json")
    return {
        **status,
        "instrumented": [
            {"span": "redteam.generate", "what": "one batch of variants"},
            {"span": "redteam.generate_one", "what": "one variant end to end"},
            {"span": "experiment.plan", "what": "parameter planning, which can reach an API"},
            {"span": "telemetry.compile", "what": "rendering the log lines"},
            {"span": "telemetry.validate", "what": "the critic replaying what was rendered"},
            {"span": "rule.validate", "what": "parsing and capping a proposed rule"},
            {"span": "replay.evaluate", "what": "the detector and correlator over a stream"},
            {"span": "stream.replay", "what": "the paced replay loop, with its wait counters"},
            {"span": "eval.variant", "what": "one variant injected and scored"},
            {"span": "eval.evaluate_all", "what": "the whole evaluation batch"},
            {"span": "elastic.bulk_ingest", "what": "building and sending the bulk payload"},
            {"span": "elastic.evaluate", "what": "translation and the fidelity check"},
        ],
        "last_offline_run": (offline or {}).get("spans") if offline else None,
    }
