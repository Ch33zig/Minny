"""Tests for the Elastic mapping, the bulk payload and the ES|QL translation.

The fidelity tests are the ones worth reading. Three of them assert that the
translation agrees with the rule walker; the fourth breaks the translator on
purpose and asserts that the agreement disappears, because a check that
cannot fail is not a check.
"""

from __future__ import annotations

import json
import socket

import pytest

from minny.elastic import bulk, documents, esql, executor, fidelity, mapping
from minny.elastic.client import ElasticClient

INDEX = "minny-test-events-v1"


# ------------------------------------------------------------- the mapping


def test_root_and_every_object_are_strict():
    body = mapping.events_mapping()["mappings"]
    assert body["dynamic"] == "strict"
    assert body["date_detection"] is False

    def walk(properties, path=""):
        for name, leaf in properties.items():
            here = f"{path}.{name}" if path else name
            if "properties" in leaf:
                # Strictness at the root does not reach an object that
                # declares its own properties, which is how a "strict"
                # mapping ends up strict about exactly one level.
                assert leaf.get("dynamic") == "strict", here
                walk(leaf["properties"], here)
            else:
                assert "type" in leaf, here

    walk(body["properties"])


def test_every_declared_field_reaches_the_mapping():
    flat = mapping.flat_fields(mapping.EVENT_FIELDS)
    properties = mapping.events_mapping()["mappings"]["properties"]
    for path, field_type in flat.items():
        node = properties
        for part in path.split(".")[:-1]:
            node = node[part]["properties"]
        assert node[path.split(".")[-1]]["type"] == field_type


def test_the_original_line_is_stored_but_not_indexed():
    flat = dict(
        (path, options) for path, _type, options in mapping.EVENT_FIELDS
    )
    assert flat["event.original"]["index"] is False


def test_index_names_are_per_workspace():
    first = mapping.index_names("one")
    second = mapping.index_names("two")
    assert first["events"] != second["events"]
    assert first["events"].endswith("-events-v1")


# ------------------------------------------------------------ the payload


def _events(count: int):
    events, _owners, _signals = fidelity.null_corpus()
    return events[:count]


def test_bulk_row_count_equals_the_source_row_count(tmp_path):
    events = _events(10)
    client = ElasticClient(url="", api_key="", workspace_id="w")
    pairs = (
        (
            documents.doc_id("w", "events", documents.event_identity(event)),
            documents.event_document(event, workspace_id="w"),
        )
        for event in events
    )
    report = bulk.index_pairs(
        client,
        INDEX,
        pairs,
        kind="events",
        out_dir=tmp_path,
        expected=len(events),
    )
    assert report["expected_count"] == len(events)
    assert report["accepted_count"] == len(events)
    assert report["complete"] is True
    assert report["verification"]["retrieved_count"] == len(events)

    # And the same count read straight off the bytes, not off the report.
    written = "".join(
        (tmp_path / name).read_text(encoding="utf-8") for name in report["files"]
    )
    actions = [
        json.loads(line)
        for position, line in enumerate(written.splitlines())
        if position % 2 == 0
    ]
    assert len(actions) == len(events)
    assert all(action["index"]["_index"] == INDEX for action in actions)
    assert len({action["index"]["_id"] for action in actions}) == len(events)


def test_the_payload_ends_in_a_newline_and_batches_are_capped():
    pairs = [(f"id{n}", {"minny": {"source_line": n}}) for n in range(1200)]
    bodies = list(bulk.batches(INDEX, pairs))
    assert len(bodies) == 3
    for body, ids in bodies:
        assert body.endswith("\n")
        assert len(ids) <= bulk.MAX_DOCS_PER_BATCH
        assert len(body.encode("utf-8")) <= bulk.MAX_BYTES_PER_BATCH


def test_an_item_failure_inside_http_200_is_not_an_accepted_document(tmp_path):
    class _Response:
        status = 200

        def read(self):
            return json.dumps(
                {
                    "errors": True,
                    "items": [
                        {"index": {"_id": "a", "status": 201}},
                        {
                            "index": {
                                "_id": "b",
                                "status": 400,
                                "error": {
                                    "type": "strict_dynamic_mapping_exception",
                                    "reason": "unknown field",
                                },
                            }
                        },
                    ],
                }
            ).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    client = ElasticClient(
        url="https://es.invalid",
        api_key="key",
        workspace_id="w",
        opener=lambda request, timeout=None: _Response(),
    )
    report = bulk.index_pairs(
        client,
        INDEX,
        [("a", {"message": "one"}), ("b", {"message": "two"})],
        kind="events",
        expected=2,
    )
    assert report["accepted_count"] == 1
    assert report["failed_count"] == 1
    assert report["complete"] is False
    assert report["failures"][0]["type"] == "strict_dynamic_mapping_exception"


# -------------------------------------------------------------- fail soft


def test_an_unreachable_cluster_fails_soft():
    def refuse(request, timeout=None):
        raise socket.timeout("timed out")

    client = ElasticClient(
        url="https://es.invalid", api_key="key", workspace_id="w", opener=refuse
    )
    ping = client.ping()
    assert ping["ok"] is False
    assert ping["error_kind"] == "unreachable"

    query = client.esql("FROM x | LIMIT 1")
    assert query["ok"] is False

    report = bulk.index_pairs(
        client, INDEX, [("a", {"message": "one"})], kind="events", expected=1
    )
    assert report["complete"] is False
    assert report["accepted_count"] == 0
    # The status route has to be able to say what went wrong without asking
    # the exception that never escaped.
    assert client.describe()["last_error"]["kind"] == "unreachable"


def test_an_online_run_does_not_delete_the_offline_payload(tmp_path):
    """Found by pointing a real run at a cluster that was not there.

    The offline payload is the artifact anyone can actually read, and an
    online attempt that fails has nothing to put in its place. Clearing the
    directory on every run destroyed it.
    """
    stale = tmp_path / "events-0001.ndjson"
    stale.write_text('{"index": {}}\n{}\n', encoding="utf-8")

    def refuse(request, timeout=None):
        raise socket.timeout("timed out")

    client = ElasticClient(
        url="https://es.invalid", api_key="key", workspace_id="w", opener=refuse
    )
    bulk.index_pairs(
        client,
        INDEX,
        [("a", {"message": "one"})],
        kind="events",
        out_dir=tmp_path,
        expected=1,
    )
    assert stale.exists()


def test_no_credentials_means_offline_and_no_request():
    def explode(request, timeout=None):  # pragma: no cover - must not run
        raise AssertionError("offline mode contacted a cluster")

    client = ElasticClient(url="", api_key="", workspace_id="w", opener=explode)
    assert client.mode == "offline"
    assert client.ping()["error_kind"] == "offline"


def test_half_a_credential_is_offline_not_an_error():
    client = ElasticClient(url="https://es.invalid", api_key="", workspace_id="w")
    assert client.configured is False
    assert client.mode == "offline"


# --------------------------------------------------------- the translation


def test_a_rule_translates_and_the_fidelity_check_passes():
    from minny.detect.rules import RuleSet

    ruleset = RuleSet.load()
    assert ruleset.rules, "detection-rules/rules.yaml has no rules to translate"

    events, owners, signals = fidelity.null_corpus()
    entries = [
        {"id": rule.id, "when": rule.when, "note": rule.name}
        for rule in ruleset.rules
    ]
    prepared = fidelity.prepare(entries, index=INDEX)
    results = fidelity.compare(
        prepared, events, owners, signals=signals, workspace_id="w"
    )
    translated = 0
    for row in results:
        # A rule is either translated and proved to agree, or refused with a
        # stated reason. What is not allowed is a query that looks like ES|QL
        # and quietly means something else.
        #
        # R002, the rule the blue agent wrote, is the refused case: a sliding
        # per-event count mixed with row predicates has no v1 ES|QL
        # equivalent, and guessing at one would put a number on screen that
        # the local walker and the cluster disagree about.
        if not row["query"]:
            assert row["fidelity"] in {"unsupported", "approximate"}, row["id"]
            assert row["reason"], f"{row['id']} was refused without saying why"
            continue

        translated += 1
        assert row["query"].startswith(f"FROM {INDEX}")
        assert row["fidelity"] == "exact", row["reason"]
        assert row["verdict"] == "agree", row["detail"]

    assert translated, "no rule in rules.yaml translated at all"


def test_every_probe_agrees_over_the_edge_corpus():
    events, owners, signals = fidelity.null_corpus()
    entries = [
        {"id": f"null_{n:02d}", "when": source, "note": note}
        for n, (source, note) in enumerate(fidelity.NULL_PROBES, start=1)
    ]
    results = fidelity.compare(
        fidelity.prepare(entries, index=INDEX),
        events,
        owners,
        signals=signals,
        workspace_id="w",
    )
    summary = fidelity.summarize(results)
    assert summary["passed"] is True
    assert summary["disagreed"] == 0
    assert summary["row_preserving"] >= 15
    # The sliding count is reported as approximate rather than quietly
    # translated into something that means a different thing.
    assert summary["approximate"] == 1


@pytest.mark.parametrize(
    "name, patch, expect_at_least",
    [
        ("naive_not_equal", "scalar", 3),
        ("unescaped_like", "like", 2),
        ("membership_without_delimiters", "collection", 2),
    ],
)
def test_the_fidelity_check_catches_a_broken_translation(
    name, patch, expect_at_least, monkeypatch
):
    """Break the translator three ways and watch the agreement disappear.

    Without this, every other fidelity assertion could be passing because the
    two evaluators share a bug rather than because the translation is right.
    """
    events, owners, signals = fidelity.null_corpus()
    entries = [
        {"id": f"null_{n:02d}", "when": source, "note": ""}
        for n, (source, note) in enumerate(fidelity.NULL_PROBES, start=1)
    ]

    if patch == "scalar":
        original = esql._scalar_predicate

        def broken(field, op, value):
            if op != "!=":
                return original(field, op, value)
            column = esql.COLUMNS[field]
            kind, raw = esql._side(value, field)
            right = (
                raw
                if kind == "column"
                else (
                    esql._number(raw)
                    if isinstance(raw, (int, float))
                    else esql.quote(raw)
                )
            )
            return f"({column} != {right})"

        monkeypatch.setattr(esql, "_scalar_predicate", broken)
    elif patch == "like":
        monkeypatch.setattr(
            esql, "like_pattern", lambda needle: esql.quote(f"*{needle}*")
        )
    else:
        original = esql._collection_predicate

        def broken(field, op, value):
            if op == "contains":
                return original(field, op, value)
            column = esql.COLUMNS[field]
            _kind, raw = esql._side(value, field)
            hit = f"{column} LIKE {esql.like_pattern(esql.escape_term(raw))}"
            if op == "==":
                return f"({column} IS NOT NULL AND {hit})"
            return f"({column} IS NULL OR NOT ({hit}))"

        monkeypatch.setattr(esql, "_collection_predicate", broken)

    results = fidelity.compare(
        fidelity.prepare(entries, index=INDEX),
        events,
        owners,
        signals=signals,
        workspace_id="w",
    )
    summary = fidelity.summarize(results)
    assert summary["passed"] is False, f"{name} went undetected"
    assert summary["disagreed"] >= expect_at_least


def test_an_untranslatable_rule_says_so_rather_than_guessing():
    result = esql.translate_source(
        "count(status=401, user=$u, window=24h) >= 5 AND ip_owner != $u",
        index=INDEX,
    )
    assert result["query"] is None
    assert result["fidelity"] == "unsupported"
    assert "count()" in result["reason"]


def test_a_sliding_count_is_labelled_approximate_not_exact():
    result = esql.translate_source(
        "count(status=401, user=$u, window=24h) >= 5", index=INDEX
    )
    assert result["fidelity"] == "approximate"
    assert "STATS matches = COUNT(*) BY window_start, user.name" in result["query"]
    assert "sliding" in result["reason"]


def test_a_rule_that_does_not_parse_produces_no_query():
    result = esql.translate_source("template == ", index=INDEX)
    assert result["query"] is None
    assert result["fidelity"] == "unsupported"


# ------------------------------------------------------------ the executor


def test_the_executor_keeps_only_true_rows():
    docs = [
        {"event": {"id": "1"}, "user": {"name": "alice_a"}},
        {"event": {"id": "2"}},
    ]
    query = (
        f"FROM {INDEX}\n"
        "| WHERE (user.name IS NOT NULL AND user.name == \"alice_a\")\n"
        "| KEEP event.id\n"
        "| LIMIT 10"
    )
    result = executor.run(query, docs)
    assert result["values"] == [["1"]]

    # NOT over a null-guarded leaf keeps the row the unguarded form drops.
    query = query.replace(
        '(user.name IS NOT NULL AND user.name == "alice_a")',
        'NOT (user.name IS NOT NULL AND user.name == "alice_a")',
    )
    assert executor.run(query, docs)["values"] == [["2"]]


def test_the_executor_reports_truncation_without_hiding_it():
    docs = [{"event": {"id": str(n)}} for n in range(10)]
    query = f"FROM {INDEX}\n| KEEP event.id\n| LIMIT 3"
    result = executor.run(query, docs)
    assert result["matched"] == 10
    assert result["returned"] == 3
    assert result["truncated"] is True


def test_the_executor_refuses_a_command_it_does_not_model():
    with pytest.raises(executor.EsqlError):
        executor.run(f"FROM {INDEX}\n| DISSECT message \"%{{a}}\"", [])


def test_the_join_delimiter_cannot_be_smuggled_through_a_term():
    terms = documents.query_terms({"q": "a|b"})
    assert documents.joined(terms) == "|q|a%7Cb|"
    assert documents.joined([]) == "|"
