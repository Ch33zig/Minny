"""Proving the ES|QL says what the rule said.

The claim being tested is narrow and worth stating exactly: *for a given
corpus of events, the set of event ids the translated ES|QL selects is the
set of event ids the Python rule walker matched.* Not "the query looks
right", not "the query parses". The same rows or a failure.

How it is tested. One pass over the events builds, for each event, both
representations at once: the feature dictionary
`minny.detect.rules.features` hands a rule, and the ECS document
`minny.elastic.documents` hands the bulk indexer. Every expression under test
is then evaluated twice against that one event, once by
`minny.detect.rules.evaluate_node` and once by the three-valued executor in
`minny.elastic.executor` running the WHERE stage of the generated query. Two
sets of line numbers come out per expression and they are compared for
equality, along with the first few lines on which they disagree.

The corpus is not only the rules in `detection-rules/rules.yaml`. One rule
exercises two operators, and a translation is wrong in the places nobody
wrote a rule for yet. `PROBES` below is a set of expressions chosen to hit
every field, every operator, both sides of every null case, LIKE wildcard
escaping, the delimiter encoding for collections, and NOT over each of them.
They are not detection rules and are never loaded by the detector; they exist
to make the translator falsifiable.

Limits, stated plainly. Agreement here proves the translation is right about
boolean structure, operator meaning and null handling, because the executor
models ES|QL's three-valued logic rather than Python's two-valued logic. It
does not prove a live cluster returns the same rows: index-time analysis,
the `ip` field type's own comparison rules, multivalued-field behaviour
outside the joined-keyword encoding, and partial results under shard failure
are all real and all unmodelled here. Those need a deployment.
"""

from __future__ import annotations

import time

from minny.detect import rules as dsl
from minny.elastic import documents, esql, executor

# Expressions whose only job is to be falsifiable. Each line names what would
# break if the translator got it wrong.
PROBES: tuple[tuple[str, str], ...] = (
    ("status == 401", "numeric equality on a field every event carries"),
    ("status >= 400", "numeric ordering"),
    ("status < 300", "the other direction, so an inverted comparison shows"),
    ("user == \"david_m\"", "keyword equality where some events have no user"),
    ("user != \"david_m\"", "the null-user rows an unguarded != would drop"),
    ("ip == \"10.0.8.45\"", "the ip field type as a keyword comparison"),
    ("ip_owner != $u", "column against column with nulls possible on both sides"),
    ("ip_owner == $u", "the same pair under equality"),
    ("NOT (ip_owner != $u)", "NOT over a leaf that is true for null rows"),
    ("obj_id > 1000", "ordering on a field that is null for most events"),
    ("obj_id != 1042", "inequality on a mostly-null numeric field"),
    ("template contains \"/api/\"", "substring match on a scalar keyword"),
    ("template contains \".\"", "a needle that is a regex metacharacter"),
    ("template contains \"?\"", "a needle that is a LIKE wildcard"),
    ("template contains \"*\"", "the other LIKE wildcard"),
    ("query contains \"csrf\"", "substring match inside a collection"),
    ("query == \"action\"", "membership in a collection, not identity"),
    ("query != \"action\"", "non-membership, including the empty collection"),
    ("signal == \"S1\"", "membership in the signals that fired on the event"),
    ("signal != \"S1\"", "its negation across every event"),
    (
        "template contains \"/api/admin/\" AND ip_owner != $u",
        "the shipped rule R001, AND over a substring and a column pair",
    ),
    (
        "status == 403 OR status == 401",
        "OR, where a wrong precedence would show as a superset",
    ),
    (
        "ip == \"10.0.8.45\" AND NOT (user == \"david_m\")",
        "NOT nested under AND, over a nullable keyword",
    ),
    (
        "status >= 200 AND status < 300",
        "a range, which is where an off-by-one in ordering shows",
    ),
)

# Probes that only mean something on the edge corpus below. Run against the
# real events they would be vacuous, because that corpus has no null user and
# no unattributable address.
#
# The count probe is here for a different reason, and it is a measured one.
# `_count_matches` walks the rolling history once per event, and a 24-hour
# window over seven months of traffic holds around 850 events, so evaluating
# it across all 180,800 rows costs about 154 million comparisons: the first
# full build spent 582 seconds in the fidelity pass and 23 seconds in
# everything else, almost all of it in that one probe. It buys nothing at
# that size, because a sliding count has no exact ES|QL to be compared
# against. Ten events prove the same point in milliseconds.
NULL_PROBES: tuple[tuple[str, str], ...] = (
    ("user == \"alice_a\"", "equality where the row's user may be null"),
    ("user != \"alice_a\"", "the rows an unguarded != drops"),
    ("ip_owner == $u", "both sides nullable, under equality"),
    ("ip_owner != $u", "both sides nullable, under inequality"),
    ("NOT (ip_owner == $u)", "NOT over a leaf that is false for null rows"),
    ("NOT (ip_owner != $u)", "NOT over a leaf that is true for null rows"),
    ("obj_id == 1042", "numeric equality where the field is usually null"),
    ("obj_id != 1042", "and its negation, which must keep the null rows"),
    ("obj_id >= 0", "ordering against null"),
    ("template contains \"?\"", "a needle that is a LIKE wildcard, with a hit"),
    ("template contains \"*\"", "the other wildcard, with a hit"),
    ("template contains \".\"", "a regex metacharacter, with a hit"),
    ("query == \"a|b\"", "a member containing the join delimiter"),
    ("query contains \"q|a\"", "a needle that would span two members unescaped"),
    ("query != \"a|b\"", "non-membership where some rows have no parameters"),
    ("query contains \"\"", "the degenerate needle, true only for a non-empty set"),
    ("signal == \"S1\"", "membership in a signal set that is empty on some rows"),
    ("signal != \"S1\"", "its negation, which must keep the empty-set rows"),
    (
        "signal == \"S11\"",
        "membership where another member has it as a prefix, which is what "
        "the delimiters around each term are for",
    ),
    (
        "user != \"alice_a\" AND ip_owner != $u",
        "two null-bearing leaves under AND",
    ),
    (
        "count(status=401, user=$u, window=24h) >= 3",
        "a sliding count, which has no exact ES|QL and is reported as such",
    ),
)

# ip -> owner, with 10.9.0.2 and 10.9.0.4 deliberately unattributable so
# ip_owner comes back null the way an address outside the baseline does.
NULL_OWNERS = {
    "10.9.0.1": "alice_a",
    "10.9.0.3": "bob_b",
}

# (line, user, ip, template, obj_id, query, status, signals)
NULL_ROWS = (
    (1, "alice_a", "10.9.0.1", "/api/a", 7, {"action": "view"}, 200, ("S1",)),
    (2, None, "10.9.0.1", "/api/a", None, {}, 401, ()),
    (3, "bob_b", "10.9.0.2", "/api/b", None, {"csrf": "x"}, 403, ("S3",)),
    (4, None, "10.9.0.2", "/api/b", 1042, {"action": None}, 200, ()),
    (5, "alice_a", "10.9.0.3", "/api/c.d", 0, {"q": "a|b"}, 500, ("S1", "S4")),
    (6, "carol_c", "10.9.0.1", "/api/e*f", -1, {"a": "*"}, 200, ()),
    (7, None, "10.9.0.4", "/api/g?h", None, {}, 200, ("S11",)),
    (8, "alice_a", "10.9.0.4", "/api/a", 1042, {"q": "a"}, 401, ()),
    (9, "alice_a", "10.9.0.4", "/api/a", 1042, {"q": "a"}, 401, ()),
    (10, "alice_a", "10.9.0.4", "/api/a", 1042, {"q": "a"}, 401, ()),
)


class _Owners:
    """The `owner_of` half of a Baselines, and nothing else.

    `minny.detect.rules.features` asks a baseline exactly one question, so a
    null corpus does not need a seven-month model behind it to answer it.
    """

    def __init__(self, owners: dict):
        self._owners = dict(owners)

    def owner_of(self, ip):
        return self._owners.get(ip)


def null_corpus():
    """A handful of events chosen so every null case actually occurs.

    The real access log has a user on every line and an owner for every
    address, so the rows that would expose a three-valued mistake are not in
    it. Agreement over a corpus where nothing is null proves nothing about
    null, which is the one thing the translation is most likely to get wrong.
    These ten rows are the counterexample corpus: null user, unattributable
    address, absent object id, empty parameter set, empty signal set, a
    parameter value containing the join delimiter, and templates carrying
    each LIKE wildcard.
    """
    from datetime import datetime, timedelta, timezone

    from minny.detect.events import from_mapping

    base = datetime(2026, 3, 15, 9, 0, 0, tzinfo=timezone(timedelta(hours=-4)))
    events = []
    signals = {}
    for line, user, ip, template, obj_id, query, status, fired in NULL_ROWS:
        events.append(
            from_mapping(
                {
                    "line": line,
                    "ts": base + timedelta(minutes=line),
                    "ip": ip,
                    "user": user,
                    "method": "GET",
                    "path": template,
                    "base": template,
                    "template": template,
                    "query": dict(query),
                    "status": status,
                    "size": 100,
                    "obj_id": obj_id,
                    "raw": f"{ip} - {user or '-'} \"GET {template}\" {status}",
                }
            )
        )
        if fired:
            signals[line] = list(fired)
    return events, _Owners(NULL_OWNERS), signals


def _where_node(query: str):
    """The WHERE stage of a generated pipeline, parsed once.

    Pulled out so the per-event loop is not re-parsing the same query 180,800
    times, and so an expression whose translation does not parse fails here
    rather than silently matching nothing.
    """
    for line in query.splitlines():
        stripped = line.strip()
        if stripped.startswith("| WHERE "):
            return executor.parse_expression(stripped[len("| WHERE "):])
    return None


def signal_index(alerts) -> dict:
    """line -> the signal ids that fired on it, read from data/alerts.json.

    The `signal` field of a rule is a property of a detector run, not of a
    log line, so the index and the Python side have to agree on where it
    comes from or the comparison measures the disagreement instead of the
    translation. Both read it from here.
    """
    index: dict = {}
    for alert in alerts or ():
        signal = alert.get("signal")
        if not signal:
            continue
        for line in alert.get("evidence_lines") or ():
            index.setdefault(int(line), set()).add(signal)
    return {line: sorted(values) for line, values in index.items()}


def prepare(expressions, *, index: str, limit: int = esql.DEFAULT_LIMIT) -> list:
    """Parse, translate and pre-compile every expression under test."""
    prepared = []
    for entry in expressions:
        if isinstance(entry, dict):
            name, source, note = entry["id"], entry["when"], entry.get("note", "")
        else:
            source, note = entry
            name = source
        parsed = dsl.parse_expression(source)
        translation = esql.translate(parsed, index=index, limit=limit)
        node = None
        error = None
        # Only an exact translation is compared row for row. An approximate
        # one still gets its Python matches recorded, because "which lines
        # does this rule fire on" is worth knowing either way, but comparing
        # a sliding count against a tumbling bucket's filter stage would be
        # measuring two different questions and calling the gap a defect.
        if translation.get("query") and translation["fidelity"] == "exact":
            try:
                node = _where_node(translation["query"])
            except executor.EsqlError as exc:
                error = f"the generated query did not parse: {exc}"
        prepared.append(
            {
                "id": name,
                "when": source,
                "note": note,
                "parsed": parsed,
                "translation": translation,
                "node": node,
                "error": error,
            }
        )
    return prepared


def compare(
    prepared,
    events,
    baselines,
    *,
    signals=None,
    workspace_id: str,
    sample: int = 5,
    keep_documents: int = 0,
) -> list:
    """One pass over the events, both evaluators, one verdict per expression.

    The event is turned into a feature dictionary and an ECS document exactly
    once and then handed to every expression, because building either of them
    per expression would make the check cost time proportional to the corpus
    times the corpus of probes.
    """
    signals = signals or {}
    state = [
        {
            "entry": entry,
            "python": set(),
            "esql": set(),
            "documents": [],
            "failures": [],
        }
        for entry in prepared
    ]
    # The rolling history a count(...) predicate reads, trimmed to the widest
    # window any expression asks for. Without it every count would be zero
    # and the recorded Python matches would be a fiction.
    window_s = max(
        (
            node.window_s
            for entry in prepared
            if entry["parsed"].ast is not None
            for node in _walk(entry["parsed"].ast)
            if isinstance(node, dsl.Count)
        ),
        default=0,
    )
    history: list = []
    scanned = 0
    started = time.perf_counter()

    for event in events:
        scanned += 1
        fired = signals.get(event.line, ())
        subject = dsl.features(event, baselines, fired)
        # Not pruned: `executor.field` reads an absent key and an explicit
        # null the same way, and pruning every document costs four times what
        # building one does. The few documents kept for the pipeline sample
        # are pruned on the way out instead.
        document = documents.event_document(
            event,
            workspace_id=workspace_id,
            ip_owner=subject.get("ip_owner"),
            signals=fired,
        )
        line = int(event.line)

        if window_s:
            history.append((subject["ts"].timestamp(), subject))
            cutoff = subject["ts"].timestamp() - window_s
            trimmed = 0
            for stamp, _ in history:
                if stamp >= cutoff:
                    break
                trimmed += 1
            if trimmed:
                del history[:trimmed]

        for slot in state:
            entry = slot["entry"]
            ast = entry["parsed"].ast
            if ast is None:
                continue
            context = dsl.EvalContext(subject, history)
            try:
                py_hit = dsl.evaluate_node(ast, context)
            except Exception as exc:  # noqa: BLE001 - record it, keep scanning
                slot["failures"].append(f"python: {type(exc).__name__}: {exc}")
                continue
            if py_hit:
                slot["python"].add(line)
            if entry["node"] is None:
                continue
            es_hit = executor.evaluate(entry["node"], document, {}) is True
            if es_hit:
                slot["esql"].add(line)
            if es_hit and len(slot["documents"]) < keep_documents:
                slot["documents"].append(documents.prune(document))

    elapsed = time.perf_counter() - started
    return [_verdict(slot, scanned, elapsed, sample) for slot in state]


def _walk(node):
    yield node
    if isinstance(node, dsl.BoolOp):
        yield from _walk(node.left)
        yield from _walk(node.right)
    elif isinstance(node, dsl.Not):
        yield from _walk(node.child)


def _verdict(slot, scanned, elapsed, sample) -> dict:
    entry = slot["entry"]
    translation = entry["translation"]
    python_lines = slot["python"]
    esql_lines = slot["esql"]
    compared = entry["node"] is not None
    only_python = sorted(python_lines - esql_lines) if compared else []
    only_esql = sorted(esql_lines - python_lines) if compared else []
    agreed = compared and not only_python and not only_esql

    if entry["parsed"].ast is None:
        verdict, detail = "not_parsed", entry["parsed"].error
    elif entry["error"]:
        verdict, detail = "executor_error", entry["error"]
    elif translation["fidelity"] == "unsupported":
        verdict, detail = "not_translated", translation["reason"]
    elif translation["fidelity"] == "approximate":
        verdict, detail = "not_compared", translation["reason"]
    elif slot["failures"]:
        verdict, detail = "evaluator_error", slot["failures"][0]
    elif agreed:
        verdict = "agree"
        detail = (
            f"both evaluators selected the same {len(python_lines)} of "
            f"{scanned} events"
        )
    else:
        verdict = "disagree"
        detail = (
            f"{len(only_python)} events matched only by the rule walker and "
            f"{len(only_esql)} only by the ES|QL"
        )

    limit = translation.get("limit")
    return {
        "id": entry["id"],
        "when": entry["when"],
        "note": entry["note"],
        "fidelity": translation["fidelity"],
        "reason": translation["reason"],
        "query": translation.get("query"),
        "verdict": verdict,
        "detail": detail,
        "agreed": agreed and translation["fidelity"] == "exact",
        "events_scanned": scanned,
        "python_matches": len(python_lines),
        "esql_matches": len(esql_lines) if compared else None,
        "only_python": only_python[:sample],
        "only_esql": only_esql[:sample],
        "matched_lines": sorted(python_lines)[:sample],
        "limit": limit,
        "limit_truncates": bool(limit) and compared and len(esql_lines) > limit,
        "documents": slot["documents"],
        "seconds": round(elapsed, 3),
    }


def summarize(results) -> dict:
    """The one-line answer, and the counts behind it."""
    compared = [row for row in results if row["fidelity"] == "exact"]
    agreed = [row for row in compared if row["agreed"]]
    approximate = [row for row in results if row["fidelity"] == "approximate"]
    untranslated = [row for row in results if row["fidelity"] == "unsupported"]
    return {
        "expressions": len(results),
        "row_preserving": len(compared),
        "agreed": len(agreed),
        "disagreed": len(compared) - len(agreed),
        "approximate": len(approximate),
        "untranslated": len(untranslated),
        "truncated_by_limit": sum(1 for row in results if row["limit_truncates"]),
        "passed": len(compared) > 0 and len(agreed) == len(compared),
        "claim": (
            "matched-line sets compared over the full event corpus; agreement "
            "covers boolean structure, operator meaning and three-valued null "
            "handling, and does not stand in for a live cluster"
        ),
    }
