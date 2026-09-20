"""Reject variants that are not worth measuring (milestone M4).

Deterministic. Not a model. A model that judges its own team's output is a
second opinion with the same blind spots, and the whole point of this stage
is to catch the cases where the generator believed something the lines do not
show.

Six checks, all of them on the rendered text after it has been parsed back
through `minny.parser`:

1. `format`: every line parses.
2. `monotonic_ts`: timestamps strictly increase.
3. `size_table`: every (path, status) -> size pair occurs in the real data.
4. `escalation_order`: a 200 on a sensitive file is either an authorized
   read or comes after an escalation step.
5. `authorization`: the victim really is authorized for the target, and the
   attacker really was denied it.
6. `operators_present`: the declared operators are visible in the output.

Check 6 is the one that is usually skipped, and it is the one that decides
whether the per-operator metrics table is a measurement or a claim.
"""

from __future__ import annotations

from dataclasses import dataclass

from minny.parser import Event, parse_line
from minny.redteam.catalog import Catalog
from minny.redteam.operators import missing_operators, privileged_actions
from minny.redteam.render import RenderedLine, SizeTable

CHECKS: tuple[str, ...] = (
    "format",
    "monotonic_ts",
    "size_table",
    "escalation_order",
    "authorization",
    "operators_present",
)


@dataclass(frozen=True)
class CriticReport:
    accepted: bool
    checks_passed: tuple[str, ...]
    rejected_reason: str | None

    def to_json(self) -> dict:
        return {
            "accepted": self.accepted,
            "checks_passed": list(self.checks_passed),
            "rejected_reason": self.rejected_reason,
        }


def review(
    lines: list[RenderedLine],
    plan,
    *,
    catalog: Catalog,
    size_table: SizeTable,
) -> tuple[CriticReport, list[Event]]:
    """Run every check in order. The first failure is the reported one."""
    passed: list[str] = []

    if not lines:
        return CriticReport(False, (), "format: variant rendered no lines"), []

    try:
        events = [parse_line(line.line, line.raw) for line in lines]
    except ValueError as exc:
        return CriticReport(False, tuple(passed), f"format: {exc}"), []
    passed.append("format")

    failure = _check_monotonic(events)
    if failure:
        return CriticReport(False, tuple(passed), failure), events
    passed.append("monotonic_ts")

    failure = _check_sizes(events, size_table)
    if failure:
        return CriticReport(False, tuple(passed), failure), events
    passed.append("size_table")

    failure = _check_escalation_order(events, catalog)
    if failure:
        return CriticReport(False, tuple(passed), failure), events
    passed.append("escalation_order")

    failure = _check_authorization(events, plan, catalog)
    if failure:
        return CriticReport(False, tuple(passed), failure), events
    passed.append("authorization")

    absent = missing_operators(list(plan.operators), events, plan, catalog)
    if absent:
        return (
            CriticReport(
                False,
                tuple(passed),
                f"operators_present: declared but not rendered: {', '.join(absent)}",
            ),
            events,
        )
    passed.append("operators_present")

    return CriticReport(True, tuple(passed), None), events


def _check_monotonic(events: list[Event]) -> str | None:
    for earlier, later in zip(events, events[1:]):
        if later.ts <= earlier.ts:
            return (
                f"monotonic_ts: line {later.line} at {later.ts.isoformat()} does "
                f"not follow line {earlier.line} at {earlier.ts.isoformat()}"
            )
    return None


def _check_sizes(events: list[Event], size_table: SizeTable) -> str | None:
    for event in events:
        if not size_table.is_consistent(event.base, event.status, event.size):
            bounds = size_table.bounds(event.base, event.status)
            return (
                f"size_table: line {event.line} carries {event.size} bytes for "
                f"({event.base}, {event.status}); the real data shows {bounds}"
            )
    return None


def _check_escalation_order(events: list[Event], catalog: Catalog) -> str | None:
    """A 200 on a sensitive file is earned or it is a hole in the story.

    Either the reader was already authorized (which is what the takeover and
    cover-download families rely on) or an escalation step happened earlier
    in the same variant.
    """
    escalations = privileged_actions(events)
    first_escalation = escalations[0].ts if escalations else None

    for event in events:
        meta = catalog.targets.get(event.base)
        if meta is None or event.status != 200:
            continue
        if event.user in meta["authorized"]:
            continue
        if first_escalation is not None and event.ts > first_escalation:
            continue
        return (
            f"escalation_order: line {event.line} gives {event.user} a 200 on "
            f"{event.base} with no prior escalation and no standing access"
        )
    return None


def _check_authorization(events: list[Event], plan, catalog: Catalog) -> str | None:
    meta = catalog.targets.get(plan.target)
    if meta is None:
        return f"authorization: {plan.target} is not in the access matrix"
    if plan.victim not in meta["authorized"]:
        return (
            f"authorization: victim {plan.victim} was never an authorized reader "
            f"of {plan.target}, so the privileged action makes no sense"
        )
    if plan.attacker in meta["authorized"]:
        return (
            f"authorization: attacker {plan.attacker} already reads {plan.target}, "
            "so there is nothing to escalate to"
        )
    if plan.attacker == plan.victim:
        return "authorization: attacker and victim are the same account"
    return None
