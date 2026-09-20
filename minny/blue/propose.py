"""The blue agent proposes a rule (milestone M6).

A proposal is a set of **parameters inside the DSL**: which fields, which
operators, which threshold, which window. It is never a string of code and it
is never a regular expression. The parameters are assembled into a `when:`
expression by `RuleSpec.when`, parsed by the grammar in
`minny.detect.rules`, and capped at depth 4 and 30 nodes like every other
rule. A proposal that does not parse is rejected before the gate ever runs,
which is the cheapest possible rejection and the one that costs nobody a
replay.

The default proposer is deterministic and seeded. It reads the evidence
packet, derives a threshold and a window from it, and scores its candidates
against the training variants and a benign sample before putting one forward.
It needs no API key and produces the same proposal on any machine, which is
what makes the gate numbers reproducible.

Claude is the optional second path, gated on `ANTHROPIC_API_KEY` exactly as
`minny.redteam.plan` gates the red team's planner. It returns the same
parameter object the deterministic proposer builds, through a strict schema,
and every value it returns is checked against the grammar before it is used.
Anything unusable degrades to the deterministic proposal for the whole rule
rather than being patched field by field: half a rule from a model and half
from a fallback is a rule nobody wrote.

Two strategies are implemented, one for each of the two proposals M6 is
expected to produce.

`auth_burst` answers `slow_guess`, which the evaluation measured switching S3
off completely (0 of 46 against 54 of 54 in the matched control). S3 counts
failures inside thirty seconds; the operator spreads the same failures over
hours. Counting per day instead of per burst keeps the claim and drops the
timing assumption.

`incident_literal` answers `param_rename`, and it is the proposal that is
meant to fail. It reads the one real incident, finds the token the attacker's
own payload parameters share, and matches on it. That rule catches March
perfectly and catches nothing else, because the string was the attacker's
choice rather than the attack's shape. It fails the first gate check, on
purpose, and the rejection is the argument for having a gate at all.
"""

from __future__ import annotations

import json
import os
import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from minny.detect import rules as dsl
from minny.detect.events import merged
from minny.eval.stream import variant_events

ANTHROPIC_MODEL = "claude-opus-5"

# Windows a human would write. A rule saying `window=41h` is a rule fitted to
# the longest chain in the sample rather than to the behaviour, and the next
# batch will contain a longer one.
WINDOW_LADDER: tuple[str, ...] = ("1h", "2h", "6h", "12h", "24h", "2d", "7d")

SEVERITIES: tuple[str, ...] = ("low", "medium", "high")


class ProposalError(ValueError):
    """A parameter object that is not expressible in the DSL."""


# ------------------------------------------------------------ the parameters


def _render_value(value: Any) -> str:
    if isinstance(value, str) and value.startswith("$"):
        return value
    if isinstance(value, bool):
        raise ProposalError("a rule value is a string or a number, not a boolean")
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    raise ProposalError(f"{value!r} cannot appear in a rule expression")


@dataclass(frozen=True)
class Predicate:
    """One comparison, or one windowed count."""

    kind: str
    field: str = ""
    op: str = "=="
    value: Any = None
    threshold: int = 0
    window: str = "24h"
    constraints: tuple = ()

    def render(self) -> str:
        if self.kind == "field":
            return f"{self.field} {self.op} {_render_value(self.value)}"
        if self.kind == "count":
            args = [f"{name}={_render_value(value)}" for name, value in self.constraints]
            args.append(f"window={self.window}")
            return f"count({', '.join(args)}) {self.op} {self.threshold}"
        raise ProposalError(f"unknown predicate kind {self.kind!r}")

    @property
    def cost(self) -> int:
        """A count walks the rolling history; a comparison reads one field."""
        return 1 if self.kind == "count" else 0


@dataclass(frozen=True)
class RuleSpec:
    """Everything a rules.yaml entry needs, before it has an id."""

    name: str
    severity: str
    explain: str
    predicates: tuple[Predicate, ...]
    rationale: str
    strategy: str
    proposer: str = "deterministic"
    join: str = "AND"
    derivation: dict = field(default_factory=dict)

    @property
    def when(self) -> str:
        """The expression, cheap predicates first.

        Ordering is not cosmetic and it is not a change of meaning: `AND`
        short-circuits in the evaluator, so putting the single-field
        comparison in front of the count means the rolling history is walked
        only for the events that already passed it. On the baseline window
        that is the difference between two seconds and two minutes, which is
        the difference between a gate that runs on every proposal and one
        that gets skipped.
        """
        if not self.predicates:
            raise ProposalError("a rule needs at least one predicate")
        ordered = sorted(self.predicates, key=lambda p: p.cost)
        return f" {self.join} ".join(p.render() for p in ordered)

    def document(self, rule_id: str, created_ts: str) -> dict:
        """The rules.yaml entry, in contract section 10 order."""
        return {
            "id": rule_id,
            "name": self.name,
            "severity": self.severity,
            "proposed_by": "blue_agent",
            "created_ts": created_ts,
            "when": self.when,
            "explain": self.explain,
        }


@dataclass(frozen=True)
class Proposal:
    """One candidate rule with its provenance, before the gate has run."""

    operator: str
    spec: RuleSpec
    parse: dsl.Parsed
    in_sample: dict

    @property
    def when(self) -> str:
        return self.spec.when


# --------------------------------------------------------- reading the rows


def pairs(row: dict) -> list[tuple[str, str]]:
    """The query parameters of one feature row, as key and value.

    `features()` flattens the query map into a tuple so a rule can ask
    whether a string appears anywhere in it. Absent parameters are already
    dropped at the event boundary, so the tuple alternates key and value.
    """
    flat = list(row.get("query") or ())
    return [(flat[i], flat[i + 1]) for i in range(0, len(flat) - 1, 2)]


def _grouped_by_variant(evidence) -> dict:
    """Feature rows back under the variant that produced them."""
    owner = {
        line: variant["variant_id"]
        for variant in evidence.variants
        for line in variant["injected_lines"]
    }
    groups: dict = defaultdict(list)
    for row in evidence.variant_features:
        groups[owner.get(row.get("line"))].append(row)
    return groups


def _window_for(seconds: float) -> str:
    for name in WINDOW_LADDER:
        if dsl._duration_seconds(name) >= seconds:
            return name
    return WINDOW_LADDER[-1]


def _rolling_max(rows: list[dict], *, status: int, window_s: int) -> int:
    """The worst count of one status for one account on one host in a window.

    This is the benign side of a threshold. A rule that fires at three has to
    be compared against how often three already happen by themselves.
    """
    history: dict = defaultdict(list)
    worst = 0
    for row in sorted(rows, key=lambda r: r["ts"]):
        if row.get("status") != status:
            continue
        if row.get("ip_owner") == row.get("user"):
            # A burst from the account's own machine is a forgotten password,
            # and the rule under construction excludes it by construction.
            continue
        key = (row.get("user"), row.get("ip"))
        stamps = history[key]
        stamps.append(row["ts"])
        cutoff = row["ts"].timestamp() - window_s
        while stamps and stamps[0].timestamp() < cutoff:
            stamps.pop(0)
        worst = max(worst, len(stamps))
    return worst


# ------------------------------------------------------- the two strategies


def _auth_burst(evidence, rng: random.Random) -> RuleSpec:
    """Count failed logins per day per foreign host, not per thirty seconds."""
    counts, spans = [], []
    for rows in _grouped_by_variant(evidence).values():
        fails = [row for row in rows if row.get("status") == 401]
        if not fails:
            continue
        per_host: dict = defaultdict(list)
        for row in fails:
            per_host[(row.get("user"), row.get("ip"))].append(row["ts"])
        stamps = max(per_host.values(), key=len)
        counts.append(len(stamps))
        spans.append((max(stamps) - min(stamps)).total_seconds())

    if not counts:
        raise ProposalError(
            f"no failed logins in the {evidence.operator} training variants; "
            f"this strategy has nothing to count"
        )

    window = _window_for(max(spans))
    window_s = dsl._duration_seconds(window)
    benign_worst = _rolling_max(
        list(evidence.benign_features), status=401, window_s=window_s
    )
    # The largest threshold that still catches every training variant, floored
    # at one more than the worst benign burst. Going lower buys nothing and
    # going higher drops variants the agent can already see.
    threshold = max(min(counts), benign_worst + 1)

    derivation = {
        "training_bursts": sorted(counts),
        "smallest_training_burst": min(counts),
        "widest_training_burst_s": round(max(spans)),
        "benign_worst_foreign_burst": benign_worst,
        "window": window,
        "threshold": threshold,
    }
    rationale = (
        f"S3 counts authentication failures inside a thirty second window. "
        f"The {len(counts)} training variants spread {min(counts)} to "
        f"{max(counts)} failures over up to "
        f"{round(max(spans) / 3600, 1)} hours, so the burst never forms and "
        f"the signal never fires. Counting the same failures per {window} "
        f"and only from a host the account does not own keeps the claim and "
        f"drops the timing assumption. The benign sample's worst run of "
        f"failures from a host the account does not own is {benign_worst}, so "
        f"the threshold is set at {threshold}."
    )

    return RuleSpec(
        name="repeated login failures from a host the account does not own",
        severity="high",
        explain=(
            "{user} failed to authenticate {count} times from {ip} within "
            "24 hours, and that host does not belong to the account."
        ),
        predicates=(
            Predicate(kind="field", field="ip_owner", op="!=", value="$u"),
            Predicate(
                kind="count",
                op=">=",
                threshold=threshold,
                window=window,
                constraints=(("status", 401), ("user", "$u"), ("ip", "$ip")),
            ),
        ),
        rationale=rationale,
        strategy="auth_burst",
        derivation=derivation,
    )


def _incident_literal(evidence, rng: random.Random) -> RuleSpec:
    """Match the string the March attacker happened to type.

    Kept deliberately. It is the rule a defender writes on the day, from the
    only incident they have, and the gate is the thing that catches it.
    """
    expected: dict = defaultdict(set)
    for row in evidence.benign_features:
        for key, _value in pairs(row):
            expected[row.get("template")].add(key)

    unexpected: dict = defaultdict(list)
    for row in evidence.incident_features:
        template = row.get("template")
        odd = [
            (key, value)
            for key, value in pairs(row)
            if key not in expected.get(template, set())
        ]
        if odd:
            unexpected[template].append(odd)

    if not unexpected:
        raise ProposalError(
            "the incident carries no parameter benign March does not already "
            "use; there is no literal to match on"
        )

    template = max(unexpected, key=lambda name: len(unexpected[name]))
    tokens: Counter = Counter()
    for odd in unexpected[template]:
        seen = set()
        for _key, value in odd:
            for token in _tokens(value):
                seen.add(token)
        tokens.update(seen)
    # The token that shows up on the most of those lines, longest first so a
    # tie between a word and its prefix picks the word.
    literal, hits = max(tokens.items(), key=lambda item: (item[1], len(item[0]), item[0]))

    derivation = {
        "template": template,
        "incident_lines": [
            row.get("line")
            for row in evidence.incident_features
            if row.get("template") == template and pairs(row)
        ],
        "unexpected_parameters": sorted(
            {key for odd in unexpected[template] for key, _value in odd}
        ),
        "literal": literal,
        "lines_carrying_the_literal": hits,
    }
    rationale = (
        f"The payload parameters on {template} in the real incident are "
        f"{', '.join(derivation['unexpected_parameters'])}, and {hits} of "
        f"those lines carry the string {literal!r} in the value. Matching on "
        f"it reproduces the March incident exactly. Whether it detects "
        f"anything else depends on whether the attacker's choice of word is "
        f"part of the attack, which is what the held-out check is for."
    )

    return RuleSpec(
        name=f"{literal} payload in a forum parameter",
        severity="high",
        explain=(
            "{user} posted to {template} from {ip} with a parameter "
            "containing " + literal + "."
        ),
        predicates=(
            Predicate(kind="field", field="template", op="==", value=template),
            Predicate(kind="field", field="query", op="contains", value=literal),
        ),
        rationale=rationale,
        strategy="incident_literal",
        derivation=derivation,
    )


def _tokens(value: str) -> list[str]:
    out, current = [], []
    for char in str(value):
        if char.isalnum():
            current.append(char)
        elif current:
            out.append("".join(current))
            current = []
    if current:
        out.append("".join(current))
    return [token for token in out if len(token) > 2]


STRATEGIES = {
    "slow_guess": _auth_burst,
    "param_rename": _incident_literal,
}


# --------------------------------------------------------- scoring in sample


def score(spec: RuleSpec, evidence, baselines) -> dict:
    """What the proposer can tell about its own candidate before the gate.

    Deliberately not the gate. It runs on the variants the proposer was given
    and on its benign sample, both of which it has already read, so a good
    score here means only that the rule expresses what its author meant. The
    held-out check is the one that counts, and it is the one this number is
    never allowed to stand in for.
    """
    parsed = dsl.parse_expression(spec.when)
    if not parsed.ok:
        return {"parses": False, "error": parsed.error, "caught": 0, "benign_hits": 0}

    ruleset = dsl.RuleSet.from_documents(
        [spec.document("R000", "1970-01-01T00:00:00-04:00")]
    )
    injected = {
        line: variant["variant_id"]
        for variant in evidence.variants
        for line in variant["injected_lines"]
    }
    events = merged(
        list(evidence.benign),
        [event for variant in evidence.variants for event in variant_events(variant)],
    )

    caught, benign_hits = set(), 0
    for event in events:
        for alert in ruleset.evaluate(event, baselines, ()):
            for line in alert["evidence_lines"]:
                if line in injected:
                    caught.add(injected[line])
                else:
                    benign_hits += 1
    return {
        "parses": True,
        "error": None,
        "variants": len(evidence.variants),
        "caught": len(caught),
        "rate": round(len(caught) / len(evidence.variants), 4)
        if evidence.variants
        else 0.0,
        "benign_sample_events": len(evidence.benign),
        "benign_hits": benign_hits,
    }


# --------------------------------------------------------------- the entry


def propose(
    *,
    operator: str,
    evidence,
    baselines,
    seed: int = 42,
    planner: str = "deterministic",
) -> Proposal:
    """One candidate rule for one evaded operator.

    `planner` follows the red team's convention: `deterministic` always uses
    the seeded path, `llm` insists on Claude, and `auto` uses Claude when
    ANTHROPIC_API_KEY is set and the seeded path when it is not.
    """
    if operator not in STRATEGIES:
        raise ValueError(
            f"no strategy for {operator}; known operators are "
            f"{', '.join(sorted(STRATEGIES))}"
        )
    if planner == "llm" and not anthropic_available():
        raise SystemExit(
            "--planner llm needs ANTHROPIC_API_KEY. The seeded proposer is "
            "the default and needs nothing."
        )

    rng = random.Random(seed)
    spec = STRATEGIES[operator](evidence, rng)

    if planner == "llm" or (planner == "auto" and anthropic_available()):
        proposed = propose_with_claude(operator=operator, evidence=evidence, spec=spec)
        if proposed is not None:
            spec = proposed

    return Proposal(
        operator=operator,
        spec=spec,
        parse=dsl.parse_expression(spec.when),
        in_sample=score(spec, evidence, baselines),
    )


# --------------------------------------------------------------------------
# Optional Claude-assisted parameter choice.
# --------------------------------------------------------------------------

# Every property required and no additional ones, which is what a strict
# structured output wants. The model fills in parameters; this file turns them
# into an expression and the grammar decides whether it is one.
PARAMETER_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "explain": {"type": "string"},
        "rationale": {"type": "string"},
        "join": {"type": "string", "enum": ["AND", "OR"]},
        "predicates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": ["field", "count"]},
                    "field": {"type": "string", "enum": list(dsl.FIELDS) + [""]},
                    "op": {"type": "string", "enum": list(dsl.OPERATORS)},
                    "value": {"type": "string"},
                    "threshold": {"type": "integer"},
                    "window": {"type": "string", "enum": list(WINDOW_LADDER)},
                    "constraints": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "field": {"type": "string", "enum": list(dsl.FIELDS)},
                                "value": {"type": "string"},
                            },
                            "required": ["field", "value"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": [
                    "kind",
                    "field",
                    "op",
                    "value",
                    "threshold",
                    "window",
                    "constraints",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["name", "severity", "explain", "rationale", "join", "predicates"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """You are the blue team on a detection system for a \
corporate web access log. The red team found an evasion: an attack variant \
that switches one of the shipped signals off. You propose one detection rule \
that closes it.

You do not write code and you do not write regular expressions. You choose \
parameters inside a fixed grammar: which field, which operator, which value, \
and for a windowed count, which constraints, window and threshold. Deterministic \
code assembles your parameters into the rule expression and a parser decides \
whether it is valid.

The rule will be validated on variants you have not seen, generated from \
different seeds and different attacker personas, and on seven months of \
benign traffic. A rule that matches a string the attacker happened to choose \
will pass on the examples you were shown and fail there. Propose the shape of \
the attack, not the spelling of one instance of it."""


def anthropic_available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def spec_from_mapping(data: dict, *, strategy: str, fallback: RuleSpec) -> RuleSpec:
    """Turn a parameter object into a spec. Raises for anything off-grammar."""
    predicates = []
    for entry in data.get("predicates") or ():
        kind = entry.get("kind")
        if kind == "field":
            predicates.append(
                Predicate(
                    kind="field",
                    field=str(entry.get("field") or ""),
                    op=str(entry.get("op") or "=="),
                    value=_coerce(entry.get("value")),
                )
            )
        elif kind == "count":
            predicates.append(
                Predicate(
                    kind="count",
                    op=str(entry.get("op") or ">="),
                    threshold=int(entry.get("threshold") or 0),
                    window=str(entry.get("window") or "24h"),
                    constraints=tuple(
                        (str(item["field"]), _coerce(item["value"]))
                        for item in entry.get("constraints") or ()
                    ),
                )
            )
        else:
            raise ProposalError(f"unknown predicate kind {kind!r}")
    if not predicates:
        raise ProposalError("the proposal carries no predicates")

    return RuleSpec(
        name=str(data.get("name") or fallback.name),
        severity=str(data.get("severity") or fallback.severity),
        explain=str(data.get("explain") or fallback.explain),
        predicates=tuple(predicates),
        rationale=str(data.get("rationale") or fallback.rationale),
        strategy=strategy,
        proposer="llm",
        join="OR" if str(data.get("join") or "AND").upper() == "OR" else "AND",
        derivation=dict(fallback.derivation),
    )


def _coerce(value):
    """A number that arrived as a string is a number. Everything else is text."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    text = str(value)
    if text.startswith("$"):
        return text
    try:
        return int(text)
    except ValueError:
        return text


def prompt_for(operator: str, evidence, spec: RuleSpec) -> str:
    """The evidence packet as text. Numbers and feature rows, no conclusions."""
    suppressed = evidence.suppression or {}
    sample_rows = [
        evidence_row
        for evidence_row in (
            _row(row) for row in list(evidence.variant_features)[:40]
        )
    ]
    benign_rows = [_row(row) for row in list(evidence.benign_features)[:20]]
    return "\n".join(
        [
            f"Evaded operator: {operator}.",
            f"Signal it suppressed: {suppressed.get('signal')} "
            f"({suppressed.get('signal_name')}), fired on "
            f"{suppressed.get('fired')} of {suppressed.get('n')} variants "
            f"carrying it against {suppressed.get('control_fired')} of "
            f"{suppressed.get('control_n')} in the matched control.",
            "",
            f"Fields a rule can read: {', '.join(dsl.FIELDS)}.",
            f"Operators: {', '.join(dsl.OPERATORS)}. Ordering comparisons are "
            f"defined on {' and '.join(dsl.NUMERIC_FIELDS)} only and contains "
            f"on {' and '.join(dsl.CONTAINS_FIELDS)} only.",
            "A count predicate takes field constraints, a window from "
            f"{', '.join(WINDOW_LADDER)}, and a numeric threshold. $u and $ip "
            "bind to the user and address of the event being evaluated.",
            f"Depth is capped at {dsl.MAX_DEPTH} and node count at "
            f"{dsl.MAX_NODES}.",
            "",
            f"{len(evidence.variants)} training variants produced these "
            f"feature rows (a sample):",
            *sample_rows,
            "",
            f"Benign March traffic, {len(evidence.benign_features)} sampled "
            f"events, first rows:",
            *benign_rows,
            "",
            "The seeded proposer would write: " + spec.when,
            "Return the parameters for one rule.",
        ]
    )


def _row(row: dict) -> str:
    return (
        f"  line={row.get('line')} user={row.get('user')} ip={row.get('ip')} "
        f"ip_owner={row.get('ip_owner')} status={row.get('status')} "
        f"template={row.get('template')} query={list(row.get('query') or ())}"
    )


def propose_with_claude(*, operator: str, evidence, spec: RuleSpec) -> RuleSpec | None:
    """Ask Claude for parameters. Returns None on any failure, never raises."""
    if not anthropic_available():
        return None
    try:
        import anthropic
    except ImportError:
        return None

    client = anthropic.Anthropic()
    try:
        response = client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": prompt_for(operator, evidence, spec)}
            ],
            output_config={
                "format": {"type": "json_schema", "schema": PARAMETER_SCHEMA}
            },
        )
    except anthropic.RateLimitError:
        return None
    except anthropic.APIStatusError:
        return None
    except anthropic.APIConnectionError:
        return None

    text = next((block.text for block in response.content if block.type == "text"), None)
    if not text:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    try:
        return spec_from_mapping(data, strategy=spec.strategy, fallback=spec)
    except (ProposalError, KeyError, TypeError, ValueError):
        # A parameter object that cannot even be assembled into an expression
        # is not a rule to be gated, it is a failed call. The seeded proposal
        # stands, and the run says which path produced it.
        return None
