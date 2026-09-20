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


# --------------------------------------------------------------- evaluation


def features(event, baselines, fired_signals=()) -> dict:
    """The feature dictionary a rule sees.

    Exactly the fields the built-in signals read, so a rule and a signal are
    looking at the same event through the same window. `signal` carries the
    ids that fired on this event, which is what lets a rule refine the
    shipped detector rather than duplicate it.
    """
    query = event.query or {}
    return {
        "user": event.user,
        "ip": event.ip,
        "ip_owner": baselines.owner_of(event.ip) if baselines else None,
        "template": event.template,
        "obj_id": event.obj_id,
        "status": event.status,
        "signal": frozenset(fired_signals),
        "query": tuple(
            str(part) for pair in query.items() for part in pair if part is not None
        ),
        "ts": event.ts,
        "line": event.line,
        "method": event.method,
        "path": event.path,
    }


def _resolve(value, subject: dict):
    if isinstance(value, Var):
        return subject.get(value.field)
    if isinstance(value, Literal):
        return value.value
    return value


def _compare(field_name: str, op: str, wanted, subject: dict) -> bool:
    """One field against one value. The only place a rule touches an event."""
    actual = subject.get(field_name)

    if field_name in ("signal", "query"):
        # Both are collections on the event, so equality means membership and
        # contains means a substring of any member.
        members = actual or ()
        if op == "contains":
            needle = str(wanted)
            return any(needle in str(member) for member in members)
        hit = any(str(member) == str(wanted) for member in members)
        return hit if op == "==" else not hit

    if op == "contains":
        return actual is not None and str(wanted) in str(actual)

    if actual is None:
        # Unknown is not equal to anything, and is not ordered against
        # anything either. `ip_owner != $u` on an address the baseline cannot
        # attribute is true, which is the answer own_ip_takeover deserves.
        return op == "!="

    if op in ORDERING:
        try:
            left, right = float(actual), float(wanted)
        except (TypeError, ValueError):
            return False
        return {
            ">=": left >= right,
            "<=": left <= right,
            ">": left > right,
            "<": left < right,
        }[op]

    same = str(actual) == str(wanted)
    return same if op == "==" else not same


class EvalContext:
    """One rule evaluation against one event.

    Holds the counts a `count(...)` predicate computed so the explanation can
    quote the number the rule actually fired on rather than recomputing it.
    """

    def __init__(self, subject: dict, history):
        self.subject = subject
        self.history = history
        self.counts: list = []

    @property
    def count(self):
        return self.counts[0] if self.counts else None


def evaluate_node(node, ctx: EvalContext) -> bool:
    if isinstance(node, BoolOp):
        if node.op == "AND":
            return evaluate_node(node.left, ctx) and evaluate_node(node.right, ctx)
        return evaluate_node(node.left, ctx) or evaluate_node(node.right, ctx)
    if isinstance(node, Not):
        return not evaluate_node(node.child, ctx)
    if isinstance(node, Compare):
        return _compare(
            node.field, node.op, _resolve(node.value, ctx.subject), ctx.subject
        )
    if isinstance(node, Count):
        total = _count_matches(node, ctx)
        ctx.counts.append(total)
        return _compare_number(total, node.op, node.threshold)
    raise RuleParseError(f"cannot evaluate {type(node).__name__}")


def _compare_number(actual, op: str, wanted) -> bool:
    return {
        "==": actual == wanted,
        "!=": actual != wanted,
        ">=": actual >= wanted,
        "<=": actual <= wanted,
        ">": actual > wanted,
        "<": actual < wanted,
    }[op]


def _count_matches(node: Count, ctx: EvalContext) -> int:
    """How many recent events satisfy every constraint.

    The event under evaluation is already in the history, so the fifth failed
    login is counted by the rule that fires on it. Walking backwards and
    stopping at the window edge keeps this proportional to the window rather
    than to the length of the replay.
    """
    cutoff = ctx.subject["ts"].timestamp() - node.window_s
    total = 0
    for stamp, past in reversed(ctx.history):
        if stamp < cutoff:
            break
        if all(
            _compare(name, "==", _resolve(value, ctx.subject), past)
            for name, value in node.constraints
        ):
            total += 1
    return total


# --------------------------------------------------------------- the ruleset


@dataclass
class Rule:
    """One entry of rules.yaml after parsing."""

    id: str
    name: str
    severity: str
    when: str
    explain: str
    parsed: Parsed
    document: dict = field(default_factory=dict)
    disabled_reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.parsed.ok and self.disabled_reason is None

    def describe(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "when": self.when,
            "explain": self.explain,
            "enabled": self.ok,
            "parse": self.parsed.as_dict(),
            "disabled_reason": self.disabled_reason,
            "proposed_by": self.document.get("proposed_by"),
            "created_ts": self.document.get("created_ts"),
            "gate": self.document.get("gate"),
        }


# A rule the gate never saw can be as broad as `status == 200`, which would
# bury the stream and the incident with it. The cap is a circuit breaker, not
# a threshold: hitting it disables the rule and says so, rather than silently
# thinning its output.
MAX_ALERTS_PER_RULE = 500

REQUIRED_KEYS = ("id", "when")


class _SafeMap(dict):
    """Explanation placeholders that were never computed read as unknown.

    An explanation is a template filled from fields. A rule author who asks
    for a field the event does not carry gets the word unknown in the
    sentence, which is honest, rather than a KeyError that would take the
    replay down.
    """

    def __missing__(self, key):
        return "unknown"


@dataclass
class RuleSet:
    """The rules on disk, reloaded when the file changes underneath us."""

    path: Any = None
    rules: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    stamp: Any = None
    loaded_ts: str | None = None
    history: Any = None
    emitted: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.history is None:
            self.history = []

    # ------------------------------------------------------------ loading

    @classmethod
    def load(cls, path=None) -> "RuleSet":
        from minny import paths

        target = paths.rules_path() if path is None else path
        ruleset = cls(path=target)
        ruleset.reload()
        return ruleset

    @classmethod
    def from_documents(cls, documents) -> "RuleSet":
        """Build from parsed YAML, for tests and for an in-memory proposal."""
        ruleset = cls(path=None)
        ruleset.rules, ruleset.errors = _compile(documents)
        return ruleset

    def _current_stamp(self):
        try:
            info = self.path.stat()
        except (OSError, AttributeError):
            return None
        return (info.st_mtime_ns, info.st_size)

    def maybe_reload(self) -> bool:
        """Re-read when the file changed. One stat call, cheap enough to poll.

        The blue agent appends to this file while a replay is running, so the
        detector has to notice without a restart. Nothing else about the
        replay is disturbed: the rolling history and the alert counters
        survive, because a reload is a change of rules, not of evidence.
        """
        if self.path is None:
            return False
        stamp = self._current_stamp()
        if stamp == self.stamp:
            return False
        self.reload()
        return True

    def reload(self) -> None:
        import datetime as _dt

        import yaml

        if self.path is None:
            return
        stamp = self._current_stamp()
        if stamp is None:
            # No file is a normal state: the blue agent has proposed nothing
            # yet. It is not an error and it is not a reason to keep stale
            # rules in memory.
            self.rules, self.errors, self.stamp = [], [], None
            return
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                document = yaml.safe_load(handle)
        except Exception as exc:  # noqa: BLE001 - a broken file is never fatal
            # The previously loaded rules stay live. A half-written file
            # caught mid-append must not disarm the detector.
            self.errors = [
                {
                    "id": None,
                    "error": f"{type(exc).__name__}: {exc}",
                    "scope": "file",
                }
            ]
            self.stamp = stamp
            return

        self.rules, self.errors = _compile(document)
        self.stamp = stamp
        self.loaded_ts = _dt.datetime.now().astimezone().isoformat(timespec="seconds")

    # --------------------------------------------------------- evaluation

    @property
    def window_s(self) -> int:
        """The longest count window any live rule asks for."""
        windows = [
            node.window_s
            for rule in self.rules
            if rule.ok
            for node in _walk(rule.parsed.ast)
            if isinstance(node, Count)
        ]
        return max(windows) if windows else 0

    def reset(self) -> None:
        """Forget the rolling history. A replay reset starts from empty."""
        self.history = []
        self.emitted = {}

    def observe(self, subject: dict) -> None:
        self.history.append((subject["ts"].timestamp(), subject))
        window = self.window_s
        if not window:
            # No rule counts anything, so no history is worth keeping.
            del self.history[:-1]
            return
        cutoff = subject["ts"].timestamp() - window
        trimmed = 0
        for stamp, _ in self.history:
            if stamp >= cutoff:
                break
            trimmed += 1
        if trimmed:
            del self.history[:trimmed]

    def evaluate(self, event, baselines, fired_signals=()) -> list:
        """Run every live rule against one event and return its alerts.

        Called after the built-in signals so `signal` carries what they found.
        Alerts come out of the same builder the signals use, which is what
        makes a rule finding indistinguishable from a shipped one downstream.
        """
        from minny.detect.signals import build_alert

        subject = features(event, baselines, fired_signals)
        self.observe(subject)
        if not self.rules:
            return []

        alerts = []
        for rule in self.rules:
            if not rule.ok:
                continue
            ctx = EvalContext(subject, self.history)
            try:
                matched = evaluate_node(rule.parsed.ast, ctx)
            except Exception as exc:  # noqa: BLE001 - one bad rule, not a crash
                rule.disabled_reason = f"evaluation failed: {exc}"
                self.errors.append(
                    {"id": rule.id, "error": rule.disabled_reason, "scope": "rule"}
                )
                continue
            if not matched:
                continue

            seen = self.emitted.get(rule.id, 0) + 1
            self.emitted[rule.id] = seen
            if seen > MAX_ALERTS_PER_RULE:
                rule.disabled_reason = (
                    f"stopped after {MAX_ALERTS_PER_RULE} alerts in one replay; "
                    f"the rule matches too much to be a finding"
                )
                self.errors.append(
                    {"id": rule.id, "error": rule.disabled_reason, "scope": "rule"}
                )
                continue

            alerts.append(_rule_alert(build_alert, rule, event, subject, ctx))
        return alerts

    def describe(self) -> dict:
        return {
            "path": str(self.path) if self.path else None,
            "loaded_ts": self.loaded_ts,
            "rules": [rule.describe() for rule in self.rules],
            "errors": list(self.errors),
            "counts": {
                "loaded": len(self.rules),
                "enabled": sum(1 for rule in self.rules if rule.ok),
                "errors": len(self.errors),
            },
        }


def _walk(node):
    if node is None:
        return
    yield node
    if isinstance(node, BoolOp):
        yield from _walk(node.left)
        yield from _walk(node.right)
    elif isinstance(node, Not):
        yield from _walk(node.child)


def _rule_alert(build_alert, rule: Rule, event, subject: dict, ctx: EvalContext) -> dict:
    fields = {
        "user": subject.get("user"),
        "ip": subject.get("ip"),
        "ip_owner": subject.get("ip_owner"),
        "template": subject.get("template"),
        "status": subject.get("status"),
        "obj_id": subject.get("obj_id"),
        "line": subject.get("line"),
        "path": subject.get("path"),
        "query": ", ".join(subject.get("query") or ()),
        "count": ctx.count,
        "rule": rule.id,
    }
    explanation = rule.explain or f"Rule {rule.id} ({rule.name}) matched."
    try:
        explanation = explanation.format_map(_SafeMap(fields))
    except (IndexError, ValueError):
        explanation = f"Rule {rule.id} ({rule.name}) matched on line {event.line}."

    value = {
        "rule_id": rule.id,
        "rule_name": rule.name,
        "when": rule.when,
        "counts": list(ctx.counts),
        "matched": {
            key: fields[key]
            for key in ("user", "ip", "ip_owner", "template", "status", "query")
            if fields[key] not in (None, "")
        },
    }
    return build_alert(
        rule.id,
        event,
        rule.severity,
        value,
        explanation,
        ip_owner=subject.get("ip_owner"),
        signal_name=rule.name,
    )


def _compile(document) -> tuple:
    """Turn a parsed YAML document into rules and errors.

    Every failure is local. A rule with no id, a duplicate id, a `when` that
    does not parse or an expression past the caps is dropped and described;
    the rules around it load normally.
    """
    rules: list = []
    errors: list = []

    if document is None:
        return rules, errors
    if not isinstance(document, list):
        return rules, [
            {
                "id": None,
                "error": "rules.yaml must be a list of rules",
                "scope": "file",
            }
        ]

    seen = set()
    for index, entry in enumerate(document):
        if not isinstance(entry, dict):
            errors.append(
                {
                    "id": None,
                    "error": f"entry {index} is not a mapping",
                    "scope": "rule",
                }
            )
            continue
        missing = [key for key in REQUIRED_KEYS if not entry.get(key)]
        if missing:
            errors.append(
                {
                    "id": entry.get("id"),
                    "error": f"missing required key(s): {', '.join(missing)}",
                    "scope": "rule",
                }
            )
            continue

        rule_id = str(entry["id"])
        if rule_id in seen:
            errors.append(
                {"id": rule_id, "error": "duplicate rule id", "scope": "rule"}
            )
            continue
        seen.add(rule_id)

        severity = str(entry.get("severity", "medium")).lower()
        if severity not in ("low", "medium", "high"):
            errors.append(
                {
                    "id": rule_id,
                    "error": f"severity {severity!r} is not low, medium or high",
                    "scope": "rule",
                }
            )
            continue

        parsed = parse_expression(entry["when"])
        rule = Rule(
            id=rule_id,
            name=str(entry.get("name") or rule_id),
            severity=severity,
            when=str(entry["when"]),
            explain=str(entry.get("explain") or ""),
            parsed=parsed,
            document=entry,
        )
        rules.append(rule)
        if not parsed.ok:
            # Kept in `rules` so the UI can render a broken rule next to the
            # working ones. `ok` is false, so it is never evaluated.
            errors.append({"id": rule_id, "error": parsed.error, "scope": "rule"})
    return rules, errors
