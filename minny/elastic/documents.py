"""Turning parsed rows into the documents the mapping accepts.

One function per source artifact, and both of them are pure: give them a row
and they hand back a dict whose every key is declared in
`minny.elastic.mapping`. Nothing here talks to a cluster, which is what makes
the offline bulk payload and a live index request literally the same bytes.

The document `_id` is a digest of the workspace, the index kind and the
source identity, never a counter. Re-running the indexer overwrites each
document with itself, so an interrupted ingest is resumed by running it
again rather than by reasoning about what got through.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from minny.elastic.mapping import PARSER_VERSION, SCHEMA_VERSION, SEVERITY_RANK

DATASET = "minny.access_log"
SOURCE_FILE = "logs.txt"

# The delimiter that makes membership on a collection expressible as a single
# LIKE. A term containing it would let one term impersonate two, so the
# character is percent-escaped on the way in and the translator escapes the
# needle the same way. See minny/elastic/esql.py.
JOIN = "|"
JOIN_ESCAPE = "%7C"


def escape_term(value) -> str:
    return str(value).replace(JOIN, JOIN_ESCAPE)


def joined(values) -> str:
    """`|a|b|c|`, and `|` for an empty collection rather than null.

    Never null: `NOT (null LIKE '*|x|*')` is null in ES|QL, and a null
    predicate drops the row. The Python evaluator keeps that row, because a
    collection that holds nothing does not hold "x".
    """
    inner = JOIN.join(escape_term(value) for value in values)
    return f"{JOIN}{inner}{JOIN}" if inner else JOIN


def query_terms(query) -> list:
    """Keys and values, in the order `minny.detect.rules.features` builds them.

    The rule grammar asks about parameters without distinguishing a name from
    a value, so both go in one collection and `query == "csrf"` is true for a
    parameter called csrf and for one whose value is csrf.
    """
    if not query:
        return []
    return [
        str(part)
        for pair in query.items()
        for part in pair
        if part is not None
    ]


def _iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return value.isoformat()


def doc_id(workspace_id: str, kind: str, identity: str) -> str:
    digest = hashlib.sha256(
        f"{workspace_id}\x1f{kind}\x1f{identity}".encode("utf-8")
    ).hexdigest()
    return digest[:40]


def event_document(
    event,
    *,
    workspace_id: str,
    ip_owner: str | None = None,
    signals=(),
    ingested: str | None = None,
    provenance: str = "cse",
    event_set_sha256: str | None = None,
) -> dict:
    """One access-log event as an ECS-shaped document."""
    now = ingested or datetime.now(timezone.utc).isoformat(timespec="seconds")
    path = event.path or ""
    query_string = path.split("?", 1)[1] if "?" in path else None
    terms = query_terms(event.query)
    signal_ids = sorted(set(signals))

    return {
        "@timestamp": _iso(event.ts),
        "event": {
            "id": str(event.line),
            "kind": "event",
            "category": "web",
            "type": "access",
            "action": "http_request",
            "outcome": "failure" if int(event.status) >= 400 else "success",
            "dataset": DATASET,
            "sequence": int(event.line),
            "ingested": now,
            "original": event.raw or "",
        },
        "message": f"{event.method} {path} {event.status}",
        "user": {"name": event.user},
        "related": {"user": event.user},
        "source": {"ip": event.ip},
        "http": {
            "request": {"method": event.method},
            "response": {
                "status_code": int(event.status),
                "body": {"bytes": int(event.size)},
            },
        },
        "url": {"path": event.base, "query": query_string},
        "minny": {
            "template": event.template,
            "obj_id": event.obj_id,
            "ip_owner": ip_owner,
            "query_terms": terms,
            "query_joined": joined(terms),
            "signals": signal_ids,
            "signals_joined": joined(signal_ids),
            "provenance": provenance,
            "ground_truth": "unclassified",
            "workspace_id": workspace_id,
            "dataset_id": DATASET,
            "source_file": SOURCE_FILE,
            "source_line": int(event.line),
            "event_set_sha256": event_set_sha256,
            "parser_version": PARSER_VERSION,
            "schema_version": SCHEMA_VERSION,
            "observed_at": now,
        },
    }


def event_identity(event) -> str:
    return f"{SOURCE_FILE}:{int(event.line)}"


def alert_document(
    alert: dict,
    *,
    workspace_id: str,
    ingested: str | None = None,
    event_set_sha256: str | None = None,
) -> dict:
    """One alert from data/alerts.json, per 00-CONTRACTS.md section 5."""
    now = ingested or datetime.now(timezone.utc).isoformat(timespec="seconds")
    severity = str(alert.get("severity") or "").lower()
    value = alert.get("value")
    return {
        "@timestamp": _iso(alert.get("ts")),
        "event": {
            "id": alert.get("alert_id"),
            "kind": "alert",
            "category": "intrusion_detection",
            "dataset": DATASET,
            "ingested": now,
            "severity": SEVERITY_RANK.get(severity, 0),
        },
        "message": alert.get("explanation") or "",
        "user": {"name": alert.get("user")},
        "related": {"user": alert.get("user")},
        "source": {"ip": alert.get("ip")},
        "minny": {
            "alert_id": alert.get("alert_id"),
            "signal": alert.get("signal"),
            "signal_name": alert.get("signal_name"),
            "severity": severity or None,
            "incident_id": alert.get("incident_id"),
            "ip_owner": alert.get("ip_owner"),
            "template": alert.get("template"),
            "obj_id": alert.get("obj_id"),
            "evidence_lines": list(alert.get("evidence_lines") or []),
            # Alert values differ by signal, which is exactly what `flattened`
            # is for: searchable without a mapping change per signal.
            "value": value if isinstance(value, dict) else None,
            "provenance": "synthetic" if alert.get("synthetic") else "cse",
            "workspace_id": workspace_id,
            "schema_version": SCHEMA_VERSION,
        },
    }


def alert_identity(alert: dict) -> str:
    return str(alert.get("alert_id"))


def prune(value):
    """Drop null leaves so a strict mapping never sees an empty object.

    Elasticsearch accepts a null value for a mapped field, but a document
    full of them is noise in the NDJSON a judge is about to read. Empty lists
    are kept: an alert with no evidence lines is a fact worth indexing.
    """
    if isinstance(value, dict):
        cleaned = {k: prune(v) for k, v in value.items()}
        return {k: v for k, v in cleaned.items() if v is not None and v != {}}
    return value


def serialize(document: dict) -> str:
    return json.dumps(prune(document), separators=(",", ":"), ensure_ascii=False)
