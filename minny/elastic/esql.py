"""Translating the rule DSL into ES|QL.

The grammar is small, which is what makes a faithful translation possible
rather than aspirational. Eight fields, seven operators, AND/OR/NOT, and a
`count(...)` with a window. Everything below is about the places where a
direct transcription would be wrong.

**Null is the whole problem.** `minny.detect.rules._compare` is two-valued:
an unknown field is not equal to anything, is not ordered against anything,
and `ip_owner != $u` on an address the baseline cannot attribute is *true*,
because an unattributable address is exactly the case that rule is hunting.
ES|QL is three-valued: a comparison touching null is null, and `WHERE` keeps
only rows that are true, so the same rule would silently drop those events.
Worse, `NOT (null)` is null, so a naive `NOT` inverts nothing.

The fix is to make every leaf **total**: each comparison is wrapped so it
evaluates to true or false and never to null. `==` becomes
`(f IS NOT NULL AND f == v)`, `!=` becomes `(f IS NULL OR f != v)`, and a
comparison between two columns guards both sides. Once every leaf is total,
AND, OR and NOT are ordinary two-valued operators and match the Python walker
node for node.

**Collections are the other problem.** `query` and `signal` are collections
on the event, and `query == "csrf"` means membership, not identity. ES|QL
returns null for a comparison against a multivalued field, so membership is
not expressible that way. `minny.elastic.documents` therefore indexes each
collection a second time as a single delimited keyword, `|a|b|c|`, and
membership becomes `LIKE "*|b|*"`. The delimiter is escaped inside terms and
inside needles, so no term can impersonate two and no substring can span a
boundary.

**What cannot be translated, and is not pretended.** `count(field=value,
window=24h)` is a sliding window evaluated per event against the preceding
history. The v1 ES|QL command set has no sliding window. A tumbling bucket
through `DATE_TRUNC` is emitted instead, the grouping keys are taken from the
constraints that bind a variable, and the result is labelled `approximate`
with the divergence written down. It is not claimed to match, and the
fidelity check does not claim it does.
"""

from __future__ import annotations

from minny.detect.rules import BoolOp, Compare, Count, Literal, Not, Var
from minny.elastic.documents import JOIN, escape_term

# The DSL field to the indexed column. `signal` and `query` resolve to the
# joined form, because that is the only form membership can be asked of.
COLUMNS = {
    "user": "user.name",
    "ip": "source.ip",
    "ip_owner": "minny.ip_owner",
    "template": "minny.template",
    "obj_id": "minny.obj_id",
    "status": "http.response.status_code",
    "signal": "minny.signals_joined",
    "query": "minny.query_joined",
}

# Where a count(...) constraint that binds a variable turns into a STATS key.
GROUP_COLUMNS = {
    "user": "user.name",
    "ip": "source.ip",
    "ip_owner": "minny.ip_owner",
    "template": "minny.template",
    "obj_id": "minny.obj_id",
    "status": "http.response.status_code",
}

COLLECTION_FIELDS = ("signal", "query")
NUMERIC_COLUMNS = ("minny.obj_id", "http.response.status_code", "event.sequence")

VAR_COLUMNS = {"user": "user.name", "ip": "source.ip"}

EVIDENCE_COLUMNS = (
    "@timestamp",
    "event.id",
    "event.sequence",
    "user.name",
    "source.ip",
    "minny.ip_owner",
    "minny.template",
    "http.response.status_code",
    "minny.obj_id",
)

# The spec's row cap for a lab-sized query. It is emitted as written and the
# fidelity report says whether it would have truncated.
DEFAULT_LIMIT = 1000

DURATION_UNITS = (
    (86400, "day", "days"),
    (3600, "hour", "hours"),
    (60, "minute", "minutes"),
    (1, "second", "seconds"),
)


class TranslationError(ValueError):
    """The expression parsed but has no ES|QL that would mean the same."""


# -------------------------------------------------------------- literals


def quote(text: str) -> str:
    """An ES|QL double-quoted string literal."""
    escaped = (
        str(text)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def like_pattern(needle: str) -> str:
    """The literal for a LIKE pattern matching `needle` anywhere.

    LIKE's wildcards are `*` and `?` and its escape is a backslash, so a
    needle containing any of the three has to be neutralised before the
    surrounding `*` are added. Skipping this is how a rule looking for the
    literal string `a*b` quietly starts matching everything.
    """
    escaped = (
        str(needle).replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
    )
    return quote(f"*{escaped}*")


def _number(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _duration_literal(seconds: int) -> str:
    for size, singular, plural in DURATION_UNITS:
        if seconds % size == 0:
            count = seconds // size
            return f"{count} {singular if count == 1 else plural}"
    return f"{seconds} seconds"


# ------------------------------------------------------------ predicates


def _side(value, field: str):
    """Resolve the right-hand side to ('column', name) or ('literal', value)."""
    if isinstance(value, Var):
        column = VAR_COLUMNS.get(value.field)
        if column is None:
            raise TranslationError(f"unknown bound variable ${value.field}")
        return "column", column
    if isinstance(value, Literal):
        return "literal", value.value
    return "literal", value


def _collection_predicate(field: str, op: str, value) -> str:
    column = COLUMNS[field]
    kind, raw = _side(value, field)
    if kind == "column":
        # The grammar never produces this: $u and $ip bind to scalars and
        # _check_comparison refuses a variable against a numeric field, but a
        # future binding would silently mean something else here.
        raise TranslationError(f"{field} cannot be compared against a column")

    if op == "contains":
        needle = escape_term(raw)
        if needle == "":
            # `contains ""` is true for any member at all, which on the joined
            # form is "the collection is not empty".
            return f'({column} IS NOT NULL AND {column} != {quote(JOIN)})'
        return f"({column} IS NOT NULL AND {column} LIKE {like_pattern(needle)})"

    member = f"{JOIN}{escape_term(raw)}{JOIN}"
    hit = f"{column} LIKE {like_pattern(member)}"
    if op == "==":
        return f"({column} IS NOT NULL AND {hit})"
    if op == "!=":
        return f"({column} IS NULL OR NOT ({hit}))"
    raise TranslationError(f"{op} is not defined on {field}")


def _scalar_predicate(field: str, op: str, value) -> str:
    column = COLUMNS[field]
    kind, raw = _side(value, field)

    if op == "contains":
        needle = str(raw)
        return f"({column} IS NOT NULL AND {column} LIKE {like_pattern(needle)})"

    if kind == "column":
        right = raw
        if op == "!=":
            return f"({column} IS NULL OR {right} IS NULL OR {column} != {right})"
        if op == "==":
            return f"({column} IS NOT NULL AND {right} IS NOT NULL AND {column} == {right})"
        raise TranslationError(f"{op} between two columns is not translated")

    rendered = (
        _number(raw) if isinstance(raw, (int, float)) and not isinstance(raw, bool)
        else quote(raw)
    )
    if op == "==":
        return f"({column} IS NOT NULL AND {column} == {rendered})"
    if op == "!=":
        # An unknown field is not equal to anything, which is the Python
        # walker's answer and the opposite of the three-valued default.
        return f"({column} IS NULL OR {column} != {rendered})"
    if op in (">=", "<=", ">", "<"):
        if column not in NUMERIC_COLUMNS:
            raise TranslationError(f"{op} is not defined on {field}")
        return f"({column} IS NOT NULL AND {column} {op} {rendered})"
    raise TranslationError(f"unknown operator {op!r}")


def predicate(node) -> str:
    """Translate one boolean node into a total ES|QL expression."""
    if isinstance(node, BoolOp):
        left = predicate(node.left)
        right = predicate(node.right)
        return f"({left} {node.op} {right})"
    if isinstance(node, Not):
        return f"(NOT {predicate(node.child)})"
    if isinstance(node, Compare):
        if node.field not in COLUMNS:
            raise TranslationError(f"unknown field {node.field!r}")
        if node.field in COLLECTION_FIELDS:
            return _collection_predicate(node.field, node.op, node.value)
        return _scalar_predicate(node.field, node.op, node.value)
    if isinstance(node, Count):
        raise TranslationError("count() is not a row predicate")
    raise TranslationError(f"cannot translate {type(node).__name__}")


# ------------------------------------------------------------- pipelines


def _count_nodes(node) -> list:
    if isinstance(node, BoolOp):
        return _count_nodes(node.left) + _count_nodes(node.right)
    if isinstance(node, Not):
        return _count_nodes(node.child)
    if isinstance(node, Count):
        return [node]
    return []


def _row_pipeline(index: str, node, *, limit: int) -> list:
    where = predicate(node)
    keep = ", ".join(EVIDENCE_COLUMNS)
    return [
        f"FROM {index}",
        f"| WHERE {where}",
        f"| KEEP {keep}",
        "| SORT @timestamp ASC, event.sequence ASC",
        f"| LIMIT {limit}",
    ]


def _count_pipeline(index: str, node: Count, *, limit: int) -> list:
    """A tumbling-bucket stand-in for a sliding count.

    A constraint that binds `$u` or `$ip` becomes a grouping key, because
    "five failures by the same user" is a `BY user.name`. A constraint
    against a literal becomes a filter. What is left over is the window
    itself, and a tumbling bucket is not a sliding one: an event four hours
    after a burst is inside the burst's 24-hour sliding window but lands in
    the next bucket whenever the bucket boundary falls between them.
    """
    filters: list[str] = []
    groups: list[str] = []
    for name, value in node.constraints:
        if isinstance(value, Var):
            column = GROUP_COLUMNS.get(name)
            if column is None:
                raise TranslationError(f"{name} cannot be a grouping key")
            if column not in groups:
                groups.append(column)
            continue
        if name in COLLECTION_FIELDS:
            filters.append(_collection_predicate(name, "==", value))
        else:
            filters.append(_scalar_predicate(name, "==", value))

    lines = [f"FROM {index}"]
    if filters:
        lines.append(f"| WHERE {' AND '.join(filters)}")
    lines.append(
        f"| EVAL window_start = DATE_TRUNC({_duration_literal(node.window_s)}, @timestamp)"
    )
    by = ", ".join(["window_start", *groups])
    lines.append(f"| STATS matches = COUNT(*) BY {by}")
    lines.append(f"| WHERE matches {node.op} {_number(node.threshold)}")
    lines.append(f"| SORT window_start ASC")
    lines.append(f"| LIMIT {limit}")
    return lines


def translate(parsed, *, index: str, limit: int = DEFAULT_LIMIT) -> dict:
    """One parsed rule expression to one ES|QL query and its fidelity claim.

    Returns, never raises. A rule that cannot be translated reports why, and
    the caller writes that down instead of a query.
    """
    if parsed is None or getattr(parsed, "ast", None) is None:
        return {
            "query": None,
            "fidelity": "unsupported",
            "reason": getattr(parsed, "error", None) or "the expression did not parse",
            "row_preserving": False,
        }

    counts = _count_nodes(parsed.ast)
    try:
        if not counts:
            lines = _row_pipeline(index, parsed.ast, limit=limit)
            return {
                "query": "\n".join(lines),
                "fidelity": "exact",
                "reason": (
                    "every comparison is row preserving and every leaf is "
                    "guarded so it is true or false, never null"
                ),
                "row_preserving": True,
                "limit": limit,
            }
        if len(counts) == 1 and isinstance(parsed.ast, Count):
            lines = _count_pipeline(index, counts[0], limit=limit)
            return {
                "query": "\n".join(lines),
                "fidelity": "approximate",
                "reason": (
                    "count() is a sliding window evaluated per event; the v1 "
                    "ES|QL command set has no sliding window, so this emits a "
                    f"tumbling {_duration_literal(counts[0].window_s)} bucket "
                    "and the two disagree whenever a bucket boundary falls "
                    "inside a burst"
                ),
                "row_preserving": False,
                "limit": limit,
            }
        return {
            "query": None,
            "fidelity": "unsupported",
            "reason": (
                "count() combined with row predicates needs two passes over "
                "different row shapes; one ES|QL pipeline cannot hold both"
            ),
            "row_preserving": False,
        }
    except TranslationError as exc:
        return {
            "query": None,
            "fidelity": "unsupported",
            "reason": str(exc),
            "row_preserving": False,
        }


def translate_source(source: str, *, index: str, limit: int = DEFAULT_LIMIT) -> dict:
    """Parse a `when:` expression and translate it, in one call."""
    from minny.detect.rules import parse_expression

    parsed = parse_expression(source)
    result = translate(parsed, index=index, limit=limit)
    result["when"] = source
    result["parse"] = parsed.as_dict()
    return result
