"""Mutation operators, and the proof that each one is really there (M4).

An operator is a named evasion aimed at one detection signal. The names are
fixed by 00-CONTRACTS.md section 8 because they are the row labels of the
per-operator metrics table, which is the most interesting number the eval
produces: it says precisely which assumption in the detector was load
bearing.

Every operator ships with a `verify` that reads the **rendered** lines, not
the plan that asked for them. That asymmetry is the point. Declaring
`slow_guess` and then rendering twenty-second gaps would turn the metrics
table into fiction, and nothing in the planner can catch that, because the
planner is the thing that was wrong.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import time

from minny.parser import Event
from minny.redteam.catalog import (
    AVATAR_TEMPLATE,
    CANONICAL_TARGET,
    CANONICAL_VICTIM,
    Catalog,
    FORUM_EDIT_TEMPLATE,
    FORUM_NEW_PATH,
    FORUM_VIEW_TEMPLATE,
    LOGIN_PATH,
    PRIVILEGED_PATH,
)

OPERATORS: tuple[str, ...] = (
    "slow_guess",
    "own_ip_takeover",
    "param_rename",
    "victim_swap",
    "target_swap",
    "business_hours",
    "delay_gap",
    "no_cleanup",
    "no_cover_download",
)

# Which families an operator can coherently apply to. `no_cover_download` is
# F4 only: F3 *is* the cover download, so dropping it there leaves nothing.
APPLICABLE: dict[str, frozenset[str]] = {
    "slow_guess": frozenset({"F1", "F4"}),
    "own_ip_takeover": frozenset({"F1", "F3", "F4"}),
    "param_rename": frozenset({"F2", "F4"}),
    "victim_swap": frozenset({"F1", "F2", "F3", "F4"}),
    "target_swap": frozenset({"F1", "F2", "F3", "F4"}),
    "business_hours": frozenset({"F1", "F2", "F3", "F4"}),
    "delay_gap": frozenset({"F1", "F2", "F3", "F4"}),
    "no_cleanup": frozenset({"F2", "F4"}),
    "no_cover_download": frozenset({"F4"}),
}

# The real payload keys, from lines 168330-168332. They are inert query-string
# identifiers and nothing else; the "post" they stand for exists in our output
# only as the request line it would have produced.
ATTACK_PARAM_KEYS: tuple[str, ...] = ("payload", "action", "script")
ATTACK_PARAM_VALUES: tuple[tuple[str, str], ...] = (
    ("payload", "csrf_test"),
    ("action", "csrf_role_update"),
    ("script", "success"),
)

# Keys that carry no attack semantics. They are not in the benign vocabulary
# for /intranet/forum/new either — only `topic` is — so a rename still trips a
# parameter-novelty signal. Dropping the extra key entirely is the stronger
# evasion, and the planner picks between the two.
INNOCUOUS_PARAM_KEYS: tuple[str, ...] = ("ref", "page", "sort", "src", "tab")

# 30 seconds is the burst window S3 uses, so anything above it counts; the
# planner aims for 30-120 minutes. Checked as a lower bound because the
# business-hours layout can only stretch a gap, never shrink it.
SLOW_GUESS_MIN_GAP_S = 1800
# S6 correlates a view with a privileged action inside 5 seconds.
DELAY_GAP_MIN_S = 900
ESCALATION_TO_EXFIL_MIN_S = 10_800

BUSINESS_START = time(9, 0)
BUSINESS_END = time(17, 0)


def failed_logins(events: list[Event]) -> list[Event]:
    return [e for e in events if e.base == LOGIN_PATH and e.status == 401]


def successful_logins(events: list[Event]) -> list[Event]:
    return [e for e in events if e.base == LOGIN_PATH and e.status == 200]


def privileged_actions(events: list[Event]) -> list[Event]:
    return [e for e in events if e.base == PRIVILEGED_PATH and e.status == 200]


def forum_posts(events: list[Event]) -> list[Event]:
    return [e for e in events if e.base == FORUM_NEW_PATH]


def cleanup_edits(events: list[Event]) -> list[Event]:
    return [e for e in events if e.template == FORUM_EDIT_TEMPLATE]


def target_successes(events: list[Event], target: str, user: str) -> list[Event]:
    return [
        e for e in events if e.base == target and e.status == 200 and e.user == user
    ]


def _views_by(events: list[Event], user: str) -> list[Event]:
    return [
        e for e in events if e.template == FORUM_VIEW_TEMPLATE and e.user == user
    ]


def _verify_slow_guess(events: list[Event], plan, catalog: Catalog) -> bool:
    fails = failed_logins(events)
    if len(fails) < 2:
        return False
    gaps = [
        (b.ts - a.ts).total_seconds() for a, b in zip(fails, fails[1:])
    ]
    return min(gaps) >= SLOW_GUESS_MIN_GAP_S


def _verify_own_ip_takeover(events: list[Event], plan, catalog: Catalog) -> bool:
    """The victim's account has to show up on a host nobody owns.

    Not merely "not the attacker's host" — an IP that belongs to some other
    employee would still resolve to an owner, and the correlator would still
    have a name to reach for.
    """
    victim_ips = {e.ip for e in events if e.user == plan.victim}
    unknown = {ip for ip in victim_ips if not catalog.is_known_ip(ip)}
    return bool(unknown)


def _verify_param_rename(events: list[Event], plan, catalog: Catalog) -> bool:
    posts = forum_posts(events)
    if not posts:
        return False
    allowed = {"topic", *INNOCUOUS_PARAM_KEYS}
    for post in posts:
        keys = set(post.query)
        if not keys or not keys.issubset(allowed):
            return False
        if any(key in ATTACK_PARAM_KEYS for key in keys):
            return False
        if any("csrf" in value for value in post.query.values()):
            return False
    return True


def _verify_victim_swap(events: list[Event], plan, catalog: Catalog) -> bool:
    if plan.victim == CANONICAL_VICTIM:
        return False
    return any(e.user == plan.victim for e in events)


def _verify_target_swap(events: list[Event], plan, catalog: Catalog) -> bool:
    if plan.target == CANONICAL_TARGET:
        return False
    return any(e.base == plan.target for e in events)


def _verify_business_hours(events: list[Event], plan, catalog: Catalog) -> bool:
    return all(
        e.ts.weekday() < 5 and BUSINESS_START <= e.ts.time() < BUSINESS_END
        for e in events
    )


def _verify_delay_gap(events: list[Event], plan, catalog: Catalog) -> bool:
    """At least one of the chain's tight couplings has actually been widened."""
    measured: list[bool] = []

    actions = privileged_actions(events)
    views = _views_by(events, plan.victim)
    if actions and views:
        priors = [v for v in views if v.ts <= actions[0].ts]
        if priors:
            gap = (actions[0].ts - priors[-1].ts).total_seconds()
            measured.append(gap >= DELAY_GAP_MIN_S)

    exfils = target_successes(events, plan.target, plan.attacker)
    if actions and exfils:
        gap = (exfils[0].ts - actions[0].ts).total_seconds()
        measured.append(gap >= ESCALATION_TO_EXFIL_MIN_S)

    logins = successful_logins(events)
    takes = target_successes(events, plan.target, plan.victim)
    if logins and takes:
        gap = (takes[0].ts - logins[0].ts).total_seconds()
        measured.append(gap >= DELAY_GAP_MIN_S)

    return any(measured)


def _verify_no_cleanup(events: list[Event], plan, catalog: Catalog) -> bool:
    return not cleanup_edits(events)


def _verify_no_cover_download(events: list[Event], plan, catalog: Catalog) -> bool:
    """No 200 on the target under the victim's name means no cover session."""
    return not target_successes(events, plan.target, plan.victim)


VERIFIERS: dict[str, Callable[[list[Event], object, Catalog], bool]] = {
    "slow_guess": _verify_slow_guess,
    "own_ip_takeover": _verify_own_ip_takeover,
    "param_rename": _verify_param_rename,
    "victim_swap": _verify_victim_swap,
    "target_swap": _verify_target_swap,
    "business_hours": _verify_business_hours,
    "delay_gap": _verify_delay_gap,
    "no_cleanup": _verify_no_cleanup,
    "no_cover_download": _verify_no_cover_download,
}


def missing_operators(
    declared: list[str], events: list[Event], plan, catalog: Catalog
) -> list[str]:
    """The declared operators that the rendered lines do not actually show."""
    absent = []
    for name in declared:
        verify = VERIFIERS.get(name)
        if verify is None or not verify(events, plan, catalog):
            absent.append(name)
    return absent


def avatar_path(post_id: int) -> str:
    return AVATAR_TEMPLATE.replace("{id}", str(post_id))
