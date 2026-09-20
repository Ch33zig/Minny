"""The rule DSL: parse, cap, evaluate, hot-reload (milestone M3).

Rules live in `detection-rules/rules.yaml` and are written by the blue agent,
which is a language model. Nothing here executes code from that file, ever.
There is no `eval`, no `exec`, no attribute lookup driven by file contents and
no regular expression compiled from one. A rule is tokenised, parsed into a
fixed set of dataclass nodes, checked against a depth cap of 4 and a node cap
of 30, and then walked by a function that only knows how to compare fields.
A rule that does not parse is skipped with its error recorded; it is never
fatal, because a malformed proposal at 03:00 must not take the watchdog down.

Grammar, per docs/handoff/00-CONTRACTS.md section 10:

    expr       := term (("AND" | "OR") term)*
    term       := "NOT"? (predicate | "(" expr ")")
    predicate  := count "(" count_args ")" op number
                | field op value
    count_args := (field "=" value)* ("," "window=" duration)?
    field      := user | ip | ip_owner | template | obj_id | status | signal
                | query
    op         := "==" | "!=" | ">=" | "<=" | ">" | "<" | "contains"
    value      := "$u" | "$ip" | quoted-string | number | bare-name
    duration   := <int>("s" | "m" | "h" | "d")

Two additions to the frozen grammar, both deliberate and both additive:

`query` is an eighth field. The field list in the contract is
user|ip|ip_owner|template|obj_id|status|signal, which cannot express a rule
about request parameters, and request parameters are where this dataset's
payloads live. `query` evaluates against the parsed query parameter keys and
values of the event under test. Membership, not identity: `query == "csrf"` is
true when any key or any value equals the string, and `query != "csrf"` is its
negation.

`contains` is a seventh operator, substring matching, and it is accepted only
on `query` and `template`. It exists so a rule can say what an overfitted rule
actually says. The March payloads literally carry `payload=csrf_test` and
`action=csrf_role_update`, so `template == "/intranet/forum/new" AND query
contains "csrf"` catches the real incident perfectly and catches nothing at
all once a variant renames the parameter. Without these two additions that
rule fails to *parse*, and the interesting thing about it, that it passes on
the case it was written from and dies at its validation gate, never gets
measured. Keywords are case-insensitive, so `CONTAINS` parses too.

Ordering operators are accepted only on the numeric fields `obj_id` and
`status`. Comparing a username with `>=` is a mistake at authoring time, and
the parser is the cheapest place to say so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MAX_DEPTH = 4
MAX_NODES = 30

FIELDS = (
    "user",
    "ip",
    "ip_owner",
    "template",
    "obj_id",
    "status",
    "signal",
    "query",
)
NUMERIC_FIELDS = ("obj_id", "status")
CONTAINS_FIELDS = ("query", "template")

COMPARISONS = ("==", "!=", ">=", "<=", ">", "<")
ORDERING = (">=", "<=", ">", "<")
OPERATORS = COMPARISONS + ("contains",)

KEYWORDS = ("and", "or", "not", "contains")
VARIABLES = {"$u": "user", "$ip": "ip"}

DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

# A window nobody writes on purpose. The rolling history is kept in memory for
# the longest window any loaded rule asks for, so an unbounded one would mean
# holding every event of a seven-month replay.
MAX_WINDOW_S = 7 * 86400
DEFAULT_WINDOW_S = 24 * 3600


class RuleParseError(ValueError):
    """Raised for anything a rule author got wrong. Never escapes the loader."""


# ---------------------------------------------------------------- tokenizer

_TOKEN = re.compile(
    r"""\s*(?:
          (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
        | (?P<duration>\d+[smhd](?![A-Za-z0-9_]))
        | (?P<number>-?\d+(?:\.\d+)?)
        | (?P<var>\$[A-Za-z_][A-Za-z0-9_]*)
        | (?P<op>==|!=|>=|<=|>|<|=)
        | (?P<punct>[(),])
        | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
        )""",
    re.VERBOSE,
)


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    pos: int


def tokenize(source: str) -> list:
    """Split a rule expression into tokens, rejecting anything unrecognised.

    The rejection is the point. A character this tokenizer does not know is a
    parse error rather than something passed through to a later stage, which
    is what keeps a model-authored string from ever reaching an interpreter.
    """
    tokens = []
    index = 0
    while index < len(source):
        if source[index].isspace():
            index += 1
            continue
        match = _TOKEN.match(source, index)
        if not match or match.end() == index:
            raise RuleParseError(
                f"unexpected character {source[index]!r} at position {index}"
            )
        kind = match.lastgroup
        text = match.group(kind)
        tokens.append(Token(kind, text, match.start(kind)))
        index = match.end()
    return tokens


def _unquote(text: str) -> str:
    body = text[1:-1]
    return body.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")


def _duration_seconds(text: str) -> int:
    seconds = int(text[:-1]) * DURATION_UNITS[text[-1]]
    if seconds <= 0:
        raise RuleParseError(f"window {text} is not a positive duration")
    if seconds > MAX_WINDOW_S:
        raise RuleParseError(
            f"window {text} exceeds the {MAX_WINDOW_S // 86400}-day maximum"
        )
    return seconds


# ---------------------------------------------------------------------- ast


@dataclass(frozen=True)
class Var:
    """`$u` or `$ip`, bound to the subject of the event under evaluation."""

    field: str


@dataclass(frozen=True)
class Literal:
    value: Any


@dataclass(frozen=True)
class Compare:
    field: str
    op: str
    value: Any


@dataclass(frozen=True)
class Count:
    """`count(...) op number` over the rolling history."""

    constraints: tuple
    window_s: int
    op: str
    threshold: float


@dataclass(frozen=True)
class Not:
    child: Any


@dataclass(frozen=True)
class BoolOp:
    op: str
    left: Any
    right: Any


def depth_of(node) -> int:
    """Nesting depth, where a bare predicate is 1."""
    if isinstance(node, BoolOp):
        return 1 + max(depth_of(node.left), depth_of(node.right))
    if isinstance(node, Not):
        return 1 + depth_of(node.child)
    return 1


def nodes_of(node) -> int:
    """Node count, matching the numbers C's proposals already report.

    A comparison counts as two, itself and the value it tests against. A
    count predicate counts as one plus one per argument, the window included.
    So `template == "x" AND query contains "y"` is 5 and the contract's R003
    example is 7, which is what the blue agent's fixture says.
    """
    if isinstance(node, BoolOp):
        return 1 + nodes_of(node.left) + nodes_of(node.right)
    if isinstance(node, Not):
        return 1 + nodes_of(node.child)
    if isinstance(node, Count):
        return 1 + len(node.constraints) + 1
    return 2


# ------------------------------------------------------------------- parser


class _Parser:
    def __init__(self, tokens: list):
        self.tokens = tokens
        self.index = 0

    # token helpers

    def peek(self) -> Token | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def next(self) -> Token:
        token = self.peek()
        if token is None:
            raise RuleParseError("expression ended early")
        self.index += 1
        return token

    def accept_keyword(self, word: str) -> bool:
        token = self.peek()
        if token and token.kind == "name" and token.text.lower() == word:
            self.index += 1
            return True
        return False

    def accept_punct(self, char: str) -> bool:
        token = self.peek()
        if token and token.kind == "punct" and token.text == char:
            self.index += 1
            return True
        return False

    def expect_punct(self, char: str) -> None:
        if not self.accept_punct(char):
            token = self.peek()
            found = token.text if token else "end of expression"
            raise RuleParseError(f"expected {char!r}, found {found!r}")

    # grammar

    def parse(self):
        node = self.expr()
        if self.peek() is not None:
            raise RuleParseError(f"unexpected trailing {self.peek().text!r}")
        return node

    def expr(self):
        node = self.term()
        while True:
            if self.accept_keyword("and"):
                node = BoolOp("AND", node, self.term())
            elif self.accept_keyword("or"):
                node = BoolOp("OR", node, self.term())
            else:
                return node

    def term(self):
        if self.accept_keyword("not"):
            return Not(self.term())
        if self.accept_punct("("):
            node = self.expr()
            self.expect_punct(")")
            return node
        return self.predicate()

    def predicate(self):
        token = self.peek()
        if token is None:
            raise RuleParseError("expression ended early")
        if token.kind == "name" and token.text.lower() == "count":
            return self.count()
        return self.comparison()

    def comparison(self):
        token = self.next()
        if token.kind != "name":
            raise RuleParseError(f"expected a field name, found {token.text!r}")
        name = token.text
        if name not in FIELDS:
            raise RuleParseError(
                f"unknown field {name!r}; known fields are {', '.join(FIELDS)}"
            )
        op = self.operator()
        value = self.value()
        _check_comparison(name, op, value)
        return Compare(name, op, value)

    def operator(self) -> str:
        token = self.next()
        if token.kind == "op" and token.text in COMPARISONS:
            return token.text
        if token.kind == "name" and token.text.lower() == "contains":
            return "contains"
        raise RuleParseError(
            f"expected an operator, found {token.text!r}; "
            f"operators are {', '.join(OPERATORS)}"
        )

    def value(self):
        token = self.next()
        if token.kind == "string":
            return Literal(_unquote(token.text))
        if token.kind == "number":
            text = token.text
            return Literal(float(text) if "." in text else int(text))
        if token.kind == "duration":
            # Only meaningful after `window=`, which consumes it directly.
            raise RuleParseError(f"{token.text!r} is a duration, not a value")
        if token.kind == "var":
            bound = VARIABLES.get(token.text)
            if bound is None:
                raise RuleParseError(
                    f"unknown variable {token.text!r}; "
                    f"bindings are {', '.join(sorted(VARIABLES))}"
                )
            return Var(bound)
        if token.kind == "name":
            if token.text.lower() in KEYWORDS:
                raise RuleParseError(f"expected a value, found keyword {token.text!r}")
            return Literal(token.text)
        raise RuleParseError(f"expected a value, found {token.text!r}")

    def count(self):
        self.next()  # the word count
        self.expect_punct("(")
        constraints = []
        window_s = DEFAULT_WINDOW_S
        window_set = False
        while not self.accept_punct(")"):
            if constraints or window_set:
                if not self.accept_punct(","):
                    token = self.peek()
                    found = token.text if token else "end of expression"
                    raise RuleParseError(f"expected ',' in count(), found {found!r}")
            name_token = self.next()
            if name_token.kind != "name":
                raise RuleParseError(
                    f"expected an argument name in count(), found {name_token.text!r}"
                )
            if not (self.peek() and self.peek().kind == "op" and self.peek().text == "="):
                raise RuleParseError(
                    f"expected '=' after {name_token.text!r} in count()"
                )
            self.next()
            if name_token.text.lower() == "window":
                token = self.next()
                if token.kind != "duration":
                    raise RuleParseError(
                        f"window takes a duration such as 24h, found {token.text!r}"
                    )
                window_s = _duration_seconds(token.text)
                window_set = True
                continue
            name = name_token.text
            if name not in FIELDS:
                raise RuleParseError(
                    f"unknown field {name!r} in count(); "
                    f"known fields are {', '.join(FIELDS)}"
                )
            value = self.value()
            _check_comparison(name, "==", value)
            constraints.append((name, value))

        op = self.operator()
        if op == "contains":
            raise RuleParseError("count() is compared with a number, not contains")
        token = self.next()
        if token.kind != "number":
            raise RuleParseError(f"count() must be compared to a number, found {token.text!r}")
        threshold = float(token.text) if "." in token.text else int(token.text)
        return Count(tuple(constraints), window_s, op, threshold)


def _check_comparison(name: str, op: str, value) -> None:
    if op == "contains":
        if name not in CONTAINS_FIELDS:
            raise RuleParseError(
                f"contains is only defined on {' and '.join(CONTAINS_FIELDS)}, "
                f"not on {name}"
            )
        if not isinstance(value, Literal) or not isinstance(value.value, str):
            raise RuleParseError("contains takes a string")
        return
    if op in ORDERING:
        if name not in NUMERIC_FIELDS:
            raise RuleParseError(
                f"{op} is only defined on {' and '.join(NUMERIC_FIELDS)}, "
                f"not on {name}"
            )
        if not isinstance(value, Literal) or isinstance(value.value, str):
            raise RuleParseError(f"{op} takes a number")
    if name in NUMERIC_FIELDS and isinstance(value, Var):
        raise RuleParseError(f"{name} cannot be compared with a bound variable")


@dataclass(frozen=True)
class Parsed:
    """The outcome of parsing one expression, reported as C's fixture shapes it."""

    ast: Any
    depth: int
    nodes: int
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "depth": self.depth,
            "nodes": self.nodes,
            "error": self.error,
        }


def parse_expression(source: str) -> Parsed:
    """Parse and cap one `when:` expression. Returns, never raises."""
    if not isinstance(source, str) or not source.strip():
        return Parsed(None, 0, 0, "the rule has no `when` expression")
    try:
        ast = _Parser(tokenize(source)).parse()
    except RuleParseError as exc:
        return Parsed(None, 0, 0, str(exc))
    except RecursionError:
        return Parsed(None, 0, 0, "expression nests too deeply to parse")

    depth = depth_of(ast)
    nodes = nodes_of(ast)
    if depth > MAX_DEPTH:
        return Parsed(None, depth, nodes, f"depth {depth} exceeds the cap of {MAX_DEPTH}")
    if nodes > MAX_NODES:
        return Parsed(None, depth, nodes, f"{nodes} nodes exceeds the cap of {MAX_NODES}")
    return Parsed(ast, depth, nodes, None)
