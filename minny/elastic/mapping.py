"""The index mappings, written out field by field.

Two things drove the shape of this file.

The first is that the mapping is `dynamic: "strict"` at the root and on every
object inside it. Dynamic mapping would happily accept a typo'd field name,
index it as text, and then quietly return nothing for the query that used the
correct name. A strict mapping rejects the document at ingest instead, which
is a loud failure at the only moment anyone is watching. Every field a
document can carry is declared here; there is no path by which an unknown
field reaches the index.

The second is that two fields exist purely so the ES|QL translation in
`minny.elastic.esql` can stay faithful. The rule grammar treats `query` and
`signal` as collections: `query == "csrf"` is true when any parameter key or
value equals that string. A multivalued keyword field cannot express that in
ES|QL, because a comparison against a multivalued field evaluates to null
rather than to a membership test. So each collection is indexed twice: once
as the natural `keyword` array for aggregation and display, and once as a
single delimited keyword string (`|a|b|c|`) that `LIKE "*|b|*"` matches
exactly when membership holds. The joined field is never null, even when the
collection is empty, because `NOT (null LIKE ...)` is null and would drop the
row that `query != "csrf"` is supposed to keep.

Field names follow ECS where ECS has a field for the concept, and live under
`minny.*` where it does not. Nothing in this repository is a process or a host
event, so the process and host sections of the spec's table are not emitted:
declaring fields no document can fill would be decoration, and a strict
mapping makes them free to add later.
"""

from __future__ import annotations

import hashlib

# The schema version travels with every document. A mapping change that is
# not backwards compatible gets a new version and a new index rather than a
# reindex argument at two in the morning.
SCHEMA_VERSION = 1
PARSER_VERSION = "minny-access-log-1"

# (path, elastic type, extra mapping options). Flat here, nested on the way
# out, so a test can read the contract as a list rather than walking a tree.
EVENT_FIELDS: tuple[tuple[str, str, dict], ...] = (
    ("@timestamp", "date", {}),
    ("event.id", "keyword", {}),
    ("event.kind", "keyword", {}),
    ("event.category", "keyword", {}),
    ("event.type", "keyword", {}),
    ("event.action", "keyword", {}),
    ("event.outcome", "keyword", {}),
    ("event.dataset", "keyword", {}),
    ("event.sequence", "long", {}),
    ("event.ingested", "date", {}),
    ("event.original", "keyword", {"index": False, "doc_values": False}),
    ("message", "text", {}),
    ("user.name", "keyword", {}),
    ("related.user", "keyword", {}),
    ("source.ip", "ip", {}),
    ("http.request.method", "keyword", {}),
    ("http.response.status_code", "long", {}),
    ("http.response.body.bytes", "long", {}),
    ("url.path", "keyword", {}),
    ("url.query", "keyword", {}),
    ("minny.template", "keyword", {}),
    ("minny.obj_id", "long", {}),
    ("minny.ip_owner", "keyword", {}),
    ("minny.query_terms", "keyword", {}),
    ("minny.query_joined", "keyword", {}),
    ("minny.signals", "keyword", {}),
    ("minny.signals_joined", "keyword", {}),
    ("minny.provenance", "keyword", {}),
    ("minny.ground_truth", "keyword", {}),
    ("minny.workspace_id", "keyword", {}),
    ("minny.dataset_id", "keyword", {}),
    ("minny.source_file", "keyword", {}),
    ("minny.source_line", "long", {}),
    ("minny.event_set_sha256", "keyword", {}),
    ("minny.parser_version", "keyword", {}),
    ("minny.schema_version", "long", {}),
    ("minny.observed_at", "date", {}),
    ("minny.raw_fields", "flattened", {}),
)

ALERT_FIELDS: tuple[tuple[str, str, dict], ...] = (
    ("@timestamp", "date", {}),
    ("event.id", "keyword", {}),
    ("event.kind", "keyword", {}),
    ("event.category", "keyword", {}),
    ("event.dataset", "keyword", {}),
    ("event.ingested", "date", {}),
    ("event.severity", "long", {}),
    ("message", "text", {}),
    ("user.name", "keyword", {}),
    ("related.user", "keyword", {}),
    ("source.ip", "ip", {}),
    ("minny.alert_id", "keyword", {}),
    ("minny.signal", "keyword", {}),
    ("minny.signal_name", "keyword", {}),
    ("minny.severity", "keyword", {}),
    ("minny.incident_id", "keyword", {}),
    ("minny.ip_owner", "keyword", {}),
    ("minny.template", "keyword", {}),
    ("minny.obj_id", "long", {}),
    ("minny.evidence_lines", "long", {}),
    ("minny.value", "flattened", {}),
    ("minny.provenance", "keyword", {}),
    ("minny.workspace_id", "keyword", {}),
    ("minny.schema_version", "long", {}),
)

# Severity as a number so ES|QL can order it; the word stays in minny.severity.
SEVERITY_RANK = {"low": 25, "medium": 50, "high": 75, "critical": 99}


def _insert(tree: dict, path: str, field_type: str, options: dict) -> None:
    """Place one dotted field into the nested `properties` tree.

    Every intermediate object gets `dynamic: "strict"` of its own. Strictness
    at the root does not propagate to an object that declares `properties`,
    which is the kind of detail that turns a strict mapping into a mapping
    that is strict about exactly one level.
    """
    parts = path.split(".")
    node = tree
    for part in parts[:-1]:
        child = node.setdefault(part, {"dynamic": "strict", "properties": {}})
        if "properties" not in child:
            raise ValueError(f"{path} collides with a leaf field")
        node = child["properties"]
    leaf = {"type": field_type}
    leaf.update(options)
    node[parts[-1]] = leaf


def build_properties(fields) -> dict:
    tree: dict = {}
    for path, field_type, options in fields:
        _insert(tree, path, field_type, options)
    return tree


def index_mapping(fields) -> dict:
    return {
        "mappings": {
            "dynamic": "strict",
            # Dates arrive as ISO 8601 with an offset, which is what
            # strict_date_optional_time accepts. No date_detection guessing.
            "date_detection": False,
            "numeric_detection": False,
            "_source": {"enabled": True},
            "properties": build_properties(fields),
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            # One workspace, one frozen event set, no time-based rollover.
            "refresh_interval": "1s",
        },
    }


def events_mapping() -> dict:
    return index_mapping(EVENT_FIELDS)


def alerts_mapping() -> dict:
    return index_mapping(ALERT_FIELDS)


def flat_fields(fields) -> dict:
    """{dotted name: elastic type}, which is what the tests assert against."""
    return {path: field_type for path, field_type, _ in fields}


def workspace_hex(workspace_id: str) -> str:
    """Index names carry a workspace digest rather than the raw name.

    The spec asks for `minny-<workspacehex>-events-v1`. A digest keeps the
    name inside Elasticsearch's character rules whatever the workspace is
    called, and keeps two workspaces from sharing an index by accident.
    """
    return hashlib.sha256(workspace_id.encode("utf-8")).hexdigest()[:12]


def index_names(workspace_id: str) -> dict:
    prefix = f"minny-{workspace_hex(workspace_id)}"
    return {
        "events": f"{prefix}-events-v1",
        "alerts": f"{prefix}-alerts-v1",
    }


MAPPINGS = {"events": events_mapping, "alerts": alerts_mapping}
