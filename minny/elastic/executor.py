"""A local executor for the ES|QL this repository emits.

This exists so the translation can be *proved* rather than asserted. There is
no cluster here, so the generated query is parsed back from its text and run
over the same documents the bulk indexer would have shipped, and the rows it
returns are compared against the rows the Python rule walker matched. If the
translator drops a null-valued row, or inverts a NOT wrongly, or lets a LIKE
span a delimiter, the two sets disagree and the fidelity check fails.

What it models, deliberately:

* **Three-valued logic.** A comparison touching null is null, `NOT null` is
  null, `null AND false` is false, `null OR true` is true, and `WHERE` keeps
  only rows that are true. Modelling this two-valued instead would make the
  check agree with the Python walker for the wrong reason, which is worse
  than no check at all.
* **The command subset** the translator emits: FROM, WHERE, EVAL with
  DATE_TRUNC, STATS COUNT(*) BY, KEEP, SORT and LIMIT. Anything else is a
  parse error here, which keeps the executor honest about its own scope.

What it is not: an Elasticsearch. It does not model index-time analysis,
multivalued-field semantics beyond the joined-keyword encoding the mapping
uses, coercion between an `ip` field and a string, or any of the distributed
behaviour that makes a partial result possible. Agreement here is evidence
that the translation is right about logic and null handling. It is not
evidence that a live cluster returns the same rows, and the fidelity report
says so in those words.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

_TOKEN = re.compile(
    r"""\s*(?:
          (?P<string>"(?:[^"\\]|\\.)*")
        | (?P<number>-?\d+(?:\.\d+)?)
        | (?P<op>==|!=|>=|<=|>|<|=)
        | (?P<punct>[(),*])
        | (?P<name>[@A-Za-z_][A-Za-z0-9_.]*)
        )""",
    re.VERBOSE,
)

KEYWORDS = {"and", "or", "not", "is", "null", "like", "asc", "desc", "by"}

UNIT_SECONDS = {
    "second": 1,
    "seconds": 1,
    "minute": 60,
    "minutes": 60,
    "hour": 3600,
    "hours": 3600,
    "day": 86400,
    "days": 86400,
}


class EsqlError(ValueError):
    """The executor refused the query. Never raised into a request handler."""


def _unescape(literal: str) -> str:
    body = literal[1:-1]
    out = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body):
            nxt = body[index + 1]
            out.append({"n": "\n", "r": "\r", "t": "\t"}.get(nxt, nxt))
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def tokenize(source: str) -> list:
    tokens = []
    position = 0
    while position < len(source):
        if source[position] in " \t\r\n":
            position += 1
            continue
        match = _TOKEN.match(source, position)
        if not match or match.end() == position:
            raise EsqlError(f"cannot read {source[position:position + 20]!r}")
        position = match.end()
        kind = match.lastgroup
        text = match.group(kind)
        if kind == "name" and text.lower() in KEYWORDS:
            kind = "keyword"
            text = text.lower()
        tokens.append((kind, text))
    return tokens


# ------------------------------------------------------------ expressions


class _Expr:
    def __init__(self, tokens, position=0):
        self.tokens = tokens
        self.position = position

    def peek(self):
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def next(self):
        token = self.peek()
        if token is None:
            raise EsqlError("expression ended early")
        self.position += 1
        return token

    def accept(self, kind, text=None) -> bool:
        token = self.peek()
        if token and token[0] == kind and (text is None or token[1] == text):
            self.position += 1
            return True
        return False

    def parse(self):
        node = self.or_expr()
        return node

    def or_expr(self):
        node = self.and_expr()
        while self.accept("keyword", "or"):
            node = ("or", node, self.and_expr())
        return node

    def and_expr(self):
        node = self.unary()
        while self.accept("keyword", "and"):
            node = ("and", node, self.unary())
        return node

    def unary(self):
        if self.accept("keyword", "not"):
            return ("not", self.unary())
        return self.primary()

    def primary(self):
        if self.accept("punct", "("):
            node = self.or_expr()
            if not self.accept("punct", ")"):
                raise EsqlError("unbalanced parenthesis")
            return node
        return self.comparison()

    def operand(self):
        kind, text = self.next()
        if kind == "string":
            return ("lit", _unescape(text))
        if kind == "number":
            return ("lit", float(text) if "." in text else int(text))
        if kind == "name":
            return ("col", text)
        raise EsqlError(f"expected a value, found {text!r}")

    def comparison(self):
        left = self.operand()
        token = self.peek()
        if token and token[0] == "keyword" and token[1] == "is":
            self.next()
            negated = self.accept("keyword", "not")
            if not self.accept("keyword", "null"):
                raise EsqlError("expected NULL after IS")
            return ("isnull", left, negated)
        if token and token[0] == "keyword" and token[1] == "like":
            self.next()
            right = self.operand()
            return ("like", left, right)
        if token and token[0] == "op":
            self.next()
            right = self.operand()
            return ("cmp", token[1], left, right)
        raise EsqlError(f"expected an operator after {left!r}")


def parse_expression(source: str):
    parser = _Expr(tokenize(source))
    node = parser.parse()
    if parser.peek() is not None:
        raise EsqlError(f"trailing tokens in {source!r}")
    return node


# ------------------------------------------------------------- evaluation


def field(document: dict, path: str):
    """Dotted lookup. An absent field is null, which is the point."""
    node = document
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
        if node is None:
            return None
    return node


def _like_regex(pattern: str) -> re.Pattern:
    out = ["^"]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            out.append(re.escape(pattern[index + 1]))
            index += 2
            continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
        index += 1
    out.append("$")
    return re.compile("".join(out), re.DOTALL)


_LIKE_CACHE: dict = {}


def _like(value, pattern: str):
    if value is None:
        return None
    compiled = _LIKE_CACHE.get(pattern)
    if compiled is None:
        compiled = _like_regex(pattern)
        _LIKE_CACHE[pattern] = compiled
    return bool(compiled.match(str(value)))


def _value(node, document: dict, extra: dict):
    kind = node[0]
    if kind == "lit":
        return node[1]
    name = node[1]
    if name in extra:
        return extra[name]
    return field(document, name)


def _compare(op: str, left, right):
    if left is None or right is None:
        return None
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    try:
        if op == ">=":
            return left >= right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        if op == "<":
            return left < right
    except TypeError:
        return None
    raise EsqlError(f"unknown operator {op!r}")


def evaluate(node, document: dict, extra: dict):
    """Three-valued. Returns True, False or None."""
    kind = node[0]
    if kind == "and":
        left = evaluate(node[1], document, extra)
        if left is False:
            return False
        right = evaluate(node[2], document, extra)
        if right is False:
            return False
        if left is None or right is None:
            return None
        return True
    if kind == "or":
        left = evaluate(node[1], document, extra)
        if left is True:
            return True
        right = evaluate(node[2], document, extra)
        if right is True:
            return True
        if left is None or right is None:
            return None
        return False
    if kind == "not":
        inner = evaluate(node[1], document, extra)
        return None if inner is None else (not inner)
    if kind == "isnull":
        present = _value(node[1], document, extra) is not None
        return present if node[2] else (not present)
    if kind == "like":
        return _like(_value(node[1], document, extra), _value(node[2], document, extra))
    if kind == "cmp":
        return _compare(
            node[1],
            _value(node[2], document, extra),
            _value(node[3], document, extra),
        )
    raise EsqlError(f"cannot evaluate {kind!r}")


# --------------------------------------------------------------- pipeline


def _split_stages(query: str) -> list:
    stages = []
    for raw in query.splitlines():
        line = raw.strip()
        if not line:
            continue
        stages.append(line[1:].strip() if line.startswith("|") else line)
    return stages


def _date_trunc(interval_seconds: int, value):
    if value is None:
        return None
    stamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    epoch = datetime(1970, 1, 1, tzinfo=stamp.tzinfo)
    offset = (stamp - epoch).total_seconds()
    floored = offset - (offset % interval_seconds)
    return (epoch + timedelta(seconds=floored)).isoformat()


_EVAL = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*DATE_TRUNC\(\s*"
    r"(?P<count>\d+)\s+(?P<unit>[a-z]+)\s*,\s*(?P<column>[@A-Za-z_][A-Za-z0-9_.]*)\s*\)$",
    re.IGNORECASE,
)
_STATS = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*COUNT\(\*\)\s+BY\s+(?P<by>.+)$",
    re.IGNORECASE,
)


def _sort_key(spec: str):
    parts = spec.split()
    return parts[0], (len(parts) > 1 and parts[1].upper() == "DESC")


def _filtered(rows, node):
    for document, extra in rows:
        if evaluate(node, document, extra) is True:
            yield document, extra


def _evaluated(rows, name, width, column):
    for document, extra in rows:
        extra[name] = _date_trunc(width, _value(("col", column), document, extra))
        yield document, extra


def run(query: str, documents, *, apply_limit: bool = True) -> dict:
    """Execute one generated pipeline over an iterable of documents.

    Rows stay lazy through WHERE and EVAL and are only materialised where a
    command genuinely needs the whole set, so a filter over the full event
    corpus holds the matches in memory rather than the corpus.
    """
    stages = _split_stages(query)
    if not stages or not stages[0].upper().startswith("FROM "):
        raise EsqlError("a query starts with FROM")

    index = stages[0][5:].strip()
    rows = ((document, {}) for document in documents)
    columns: list | None = None
    limit = None
    truncated = False

    for stage in stages[1:]:
        head, _, rest = stage.partition(" ")
        verb = head.upper()
        rest = rest.strip()

        if verb == "WHERE":
            rows = _filtered(rows, parse_expression(rest))
        elif verb == "EVAL":
            match = _EVAL.match(rest)
            if not match:
                raise EsqlError(f"only DATE_TRUNC is supported in EVAL: {rest!r}")
            seconds = UNIT_SECONDS.get(match.group("unit").lower())
            if seconds is None:
                raise EsqlError(f"unknown interval unit {match.group('unit')!r}")
            width = int(match.group("count")) * seconds
            rows = _evaluated(rows, match.group("name"), width, match.group("column"))
        elif verb == "STATS":
            match = _STATS.match(rest)
            if not match:
                raise EsqlError(f"only COUNT(*) BY is supported in STATS: {rest!r}")
            name = match.group("name")
            keys = [part.strip() for part in match.group("by").split(",")]
            buckets: dict = {}
            for document, extra in rows:
                signature = tuple(
                    _value(("col", key), document, extra) for key in keys
                )
                buckets[signature] = buckets.get(signature, 0) + 1
            rows = [
                ({}, dict(zip(keys, signature), **{name: total}))
                for signature, total in buckets.items()
            ]
            columns = [*keys, name]
        elif verb == "KEEP":
            columns = [part.strip() for part in rest.split(",")]
        elif verb == "SORT":
            specs = [_sort_key(part.strip()) for part in rest.split(",")]
            rows = list(rows)
            for column, descending in reversed(specs):
                rows.sort(
                    key=lambda row, c=column: (
                        _value(("col", c), row[0], row[1]) is None,
                        _sortable(_value(("col", c), row[0], row[1])),
                    ),
                    reverse=descending,
                )
        elif verb == "LIMIT":
            limit = int(rest)
        else:
            raise EsqlError(f"unsupported command {verb!r}")

    rows = list(rows)
    matched = len(rows)
    if limit is not None and matched > limit:
        truncated = True
        if apply_limit:
            rows = rows[:limit]

    if columns is None:
        columns = list(EVIDENCE_DEFAULT)
    values = [
        [_value(("col", column), document, extra) for column in columns]
        for document, extra in rows
    ]
    return {
        "index": index,
        "columns": columns,
        "values": values,
        "matched": matched,
        "returned": len(values),
        "limit": limit,
        "truncated": truncated,
    }


EVIDENCE_DEFAULT = ("@timestamp", "event.id")


def _sortable(value):
    """A total order across the types a column can hold, nulls aside."""
    if value is None:
        return (0, 0.0, "")
    if isinstance(value, bool):
        return (1, float(value), "")
    if isinstance(value, (int, float)):
        return (1, float(value), "")
    return (2, 0.0, str(value))
