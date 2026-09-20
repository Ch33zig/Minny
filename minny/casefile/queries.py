"""Saved forensic queries, one per claim in the case file (milestone M1).

Every finding in `data/case_file.json` names one of these functions and ships
the line numbers it returned. Nothing in the case file is prose about data
nobody can re-derive: run `python -m minny.casefile.queries` and the numbers
behind every claim print out again from `data/events.parquet`.

Each query returns a `QueryResult` carrying the evidence lines plus the counts
its claim leans on, so the wording in the case file is generated from measured
values rather than typed from memory.
"""

from __future__ import annotations

import functools
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

import pandas as pd

from minny import paths

# March 2026 is held out everywhere else in the project, and the user/IP
# baseline is fitted the same way for the same reason: the attack must never
# be allowed to redefine what normal looks like.
# Single definition, shared with the detector so the case file and the
# baselines can never disagree about where March begins.
from minny.build_events import BASELINE_CUTOFF  # noqa: E402

# The prefix case_file.json uses when naming a query, per 00-CONTRACTS.md §7.
QUERY_NAMESPACE = "casefile.queries"

FORUM_NEW = "/intranet/forum/new"
FORUM_VIEW = "/intranet/forum/view/{id}"
FORUM_EDIT = "/intranet/forum/edit/{id}"
CONFIDENTIAL_MARKER = "CONFIDENTIAL"
SENSITIVE_PREFIXES = "/finance/|/hr/|/exec/|/it/"
PRIVILEGED_PREFIX = "/api/admin/"

# Nothing alerts on the clock. This window exists only so the dismissed
# off-hours lead can be measured rather than asserted.
OFF_HOURS_START = 20
OFF_HOURS_END = 6


@dataclass(frozen=True)
class QueryResult:
    """What one saved query found, and the counts its claim rests on."""

    name: str
    question: str
    lines: list[int]
    stats: dict = field(default_factory=dict)

    @property
    def qualified_name(self) -> str:
        return f"{QUERY_NAMESPACE}.{self.name}"

    def to_dict(self) -> dict:
        return {
            "query": self.qualified_name,
            "question": self.question,
            "lines": self.lines,
            "stats": self.stats,
        }


QUERIES: dict[str, Callable[..., QueryResult]] = {}


def saved(question: str) -> Callable:
    """Register a query so the case file can name it and anyone can re-run it."""

    def decorate(fn: Callable[..., QueryResult]) -> Callable[..., QueryResult]:
        fn.question = question  # type: ignore[attr-defined]
        QUERIES[fn.__name__] = fn
        return fn

    return decorate


@functools.lru_cache(maxsize=1)
def load_events() -> pd.DataFrame:
    """The canonical events table, read once per process."""
    return pd.read_parquet(paths.require(paths.events_path()))


def _events(events: pd.DataFrame | None) -> pd.DataFrame:
    return load_events() if events is None else events


def _lines(frame: pd.DataFrame) -> list[int]:
    return [int(value) for value in frame["line"].tolist()]


def _iso(value) -> str | None:
    """ISO 8601 with offset. A naive datetime is a four-hour bug downstream."""
    if value is None or pd.isna(value):
        return None
    return pd.Timestamp(value).isoformat()


def _query_keys(value) -> tuple[str, ...]:
    """Parameter names actually present on a request.

    The parquet round trip stores `query` as a struct, so every row carries
    every key the column ever saw, with `None` where the parameter was absent.
    An absent parameter is not an empty one, so the Nones are dropped here
    instead of being counted as evidence of tampering.
    """
    if value is None:
        return ()
    try:
        items = dict(value).items()
    except (TypeError, ValueError):
        return ()
    return tuple(sorted(key for key, val in items if val is not None))


def baseline_ip_by_user(
    events: pd.DataFrame | None = None, cutoff: datetime = BASELINE_CUTOFF
) -> dict[str, str]:
    """Each user's source IP, fitted before the incident window."""
    frame = _events(events)
    baseline = frame[(frame["ts"] < cutoff) & frame["user"].notna()]
    return {
        str(user): str(group["ip"].value_counts().idxmax())
        for user, group in baseline.groupby("user")
    }


# --- F1 --------------------------------------------------------------------


@saved("Which requests come from an IP the user has never worked from?")
def ip_user_mismatch(
    events: pd.DataFrame | None = None, cutoff: datetime = BASELINE_CUTOFF
) -> QueryResult:
    """Requests whose source IP is not the user's fitted baseline IP.

    This is arithmetic, not a score. Every user appears on exactly one IP for
    seven months, so a second IP is a broken binding rather than an unusual
    value on a curve.
    """
    frame = _events(events)
    owner = baseline_ip_by_user(frame, cutoff)

    named = frame[frame["user"].notna()]
    ips_per_user = named.groupby("user")["ip"].nunique().to_dict()
    baseline_ips_per_user = (
        named[named["ts"] < cutoff].groupby("user")["ip"].nunique().to_dict()
    )

    known = named.copy()
    known["baseline_ip"] = known["user"].map(owner)
    hits = known[known["ip"] != known["baseline_ip"]].sort_values("line")

    offenders = sorted(hits["user"].dropna().unique().tolist())
    foreign_ips = sorted(hits["ip"].unique().tolist())
    ip_owner = {ip: user for user, ip in owner.items()}

    return QueryResult(
        name="ip_user_mismatch",
        question=ip_user_mismatch.question,  # type: ignore[attr-defined]
        lines=_lines(hits),
        stats={
            "baseline_ip_by_user": owner,
            "user_count": len(owner),
            # Per user, so a suspect card can cite its own number rather than
            # inherit the aggregate.
            "ips_per_user": {str(k): int(v) for k, v in ips_per_user.items()},
            "baseline_ips_per_user": {
                str(k): int(v) for k, v in baseline_ips_per_user.items()
            },
            "users_with_one_ip_overall": sum(1 for n in ips_per_user.values() if n == 1),
            "users_with_one_ip_in_baseline": sum(
                1 for n in baseline_ips_per_user.values() if n == 1
            ),
            "violating_users": offenders,
            "foreign_ips": foreign_ips,
            "foreign_ip_owners": [ip_owner.get(ip) for ip in foreign_ips],
            "months_observed": int(
                named[named["user"].isin(offenders)]["ts"]
                .dt.tz_localize(None)
                .dt.to_period("M")
                .nunique()
            ),
            "baseline_months": int(
                named[named["ts"] < cutoff]["ts"]
                .dt.tz_localize(None)
                .dt.to_period("M")
                .nunique()
            ),
            "first_ts": _iso(hits["ts"].min()),
            "last_ts": _iso(hits["ts"].max()),
            "statuses": {
                str(k): int(v) for k, v in hits["status"].value_counts().items()
            },
        },
    )


# --- F2 --------------------------------------------------------------------


def _auth_fail_runs(events: pd.DataFrame, max_gap_s: float) -> list[pd.DataFrame]:
    """Split every 401 into maximal same-user, same-IP runs inside max_gap_s."""
    failures = events[events["status"] == 401].sort_values(["user", "ip", "ts"])
    if failures.empty:
        return []

    same_session = (failures["user"] == failures["user"].shift()) & (
        failures["ip"] == failures["ip"].shift()
    )
    gap = failures["ts"].diff().dt.total_seconds()
    starts_run = ~(same_session & gap.between(0, max_gap_s, inclusive="left"))
    run_id = starts_run.cumsum()
    return [group.sort_values("line") for _, group in failures.groupby(run_id)]


@saved("Are there runs of failed logins fast enough to be guessing?")
def auth_fail_burst(
    events: pd.DataFrame | None = None,
    min_length: int = 3,
    max_gap_s: float = 15.0,
) -> QueryResult:
    """Consecutive 401s from one user and IP with sub-15-second gaps.

    The second half of this query matters more than the first. Two bursts is
    interesting; two bursts and no third anywhere in 180,800 lines is the
    finding, so the runs that fall short are counted here too.
    """
    frame = _events(events)
    runs = _auth_fail_runs(frame, max_gap_s)

    bursts = [run for run in runs if len(run) >= min_length]
    short = [run for run in runs if len(run) < min_length]

    lines: list[int] = []
    detail = []
    for run in bursts:
        run_lines = _lines(run)
        lines.extend(run_lines)
        gaps = run["ts"].diff().dt.total_seconds().dropna().tolist()
        detail.append(
            {
                "lines": run_lines,
                "user": str(run.iloc[0]["user"]),
                "ip": str(run.iloc[0]["ip"]),
                "start_ts": _iso(run["ts"].min()),
                "end_ts": _iso(run["ts"].max()),
                "attempts": len(run_lines),
                "gaps_s": [float(gap) for gap in gaps],
            }
        )

    failures = frame[frame["status"] == 401]
    outside = failures[~failures["line"].isin(lines)]
    # How close does the rest of the file ever come to a burst? If the nearest
    # pair is hours apart, the two bursts are not the tail of a distribution.
    outside_gaps = (
        outside.sort_values(["user", "ip", "ts"])
        .groupby(["user", "ip"])["ts"]
        .diff()
        .dt.total_seconds()
        .dropna()
    )

    return QueryResult(
        name="auth_fail_burst",
        question=auth_fail_burst.question,  # type: ignore[attr-defined]
        lines=sorted(lines),
        stats={
            "min_length": min_length,
            "max_gap_s": max_gap_s,
            "burst_count": len(bursts),
            "bursts": detail,
            "burst_users": sorted({entry["user"] for entry in detail}),
            "total_401": int(len(failures)),
            "in_burst_401": len(lines),
            "isolated_401": int(len(failures)) - len(lines),
            "runs_of_two": sum(1 for run in short if len(run) == 2),
            "min_gap_s_outside_bursts": (
                float(outside_gaps.min()) if not outside_gaps.empty else None
            ),
            "median_gap_s_outside_bursts": (
                float(outside_gaps.median()) if not outside_gaps.empty else None
            ),
        },
    )


# --- F3 --------------------------------------------------------------------


@saved("Does any forum post carry a parameter the application never uses?")
def tampered_forum_post(events: pd.DataFrame | None = None) -> QueryResult:
    """Posts to /intranet/forum/new with a query key other than `topic`."""
    frame = _events(events)
    posts = frame[frame["base"] == FORUM_NEW].copy()
    posts["keys"] = posts["query"].map(_query_keys)

    odd = posts[posts["keys"].map(lambda keys: any(k != "topic" for k in keys))]
    odd = odd.sort_values("line")

    extra = Counter(key for keys in odd["keys"] for key in keys if key != "topic")
    parameterised = frame[frame["query"].map(lambda q: bool(_query_keys(q)))]

    return QueryResult(
        name="tampered_forum_post",
        question=tampered_forum_post.question,  # type: ignore[attr-defined]
        lines=_lines(odd),
        stats={
            "forum_new_requests": int(len(posts)),
            "topic_only_requests": int(len(posts) - len(odd)),
            "tampered_requests": int(len(odd)),
            "unexpected_keys": dict(sorted(extra.items())),
            "paths": odd["path"].tolist(),
            "statuses": [int(status) for status in odd["status"].tolist()],
            "users": sorted(odd["user"].dropna().unique().tolist()),
            # No other path in the file ever carries a query string at all, so
            # the parameter set is a contract the attacker broke rather than a
            # convention he bent.
            "paths_with_any_parameter": sorted(parameterised["base"].unique().tolist()),
        },
    )


# --- F4 --------------------------------------------------------------------


@saved("Which request templates occur exactly once in the whole file?")
def globally_unique_templates(
    events: pd.DataFrame | None = None, max_occurrences: int = 1
) -> QueryResult:
    """Templates seen once in 180,800 lines.

    Templates, not paths: every forum post is its own path, so on raw paths
    "never seen before" would fire on ordinary browsing.
    """
    frame = _events(events)
    counts = frame["template"].value_counts()
    rare = counts[counts <= max_occurrences]
    common = counts[counts > max_occurrences]

    hits = frame[frame["template"].isin(rare.index)].sort_values("line")

    return QueryResult(
        name="globally_unique_templates",
        question=globally_unique_templates.question,  # type: ignore[attr-defined]
        lines=_lines(hits),
        stats={
            "max_occurrences": max_occurrences,
            "template_count": int(len(counts)),
            "unique_templates": {str(k): int(v) for k, v in rare.items()},
            "next_rarest_template": str(common.idxmin()) if not common.empty else None,
            "next_rarest_count": int(common.min()) if not common.empty else None,
            "users": sorted(hits["user"].dropna().unique().tolist()),
            "events": [
                {
                    "line": int(row["line"]),
                    "ts": _iso(row["ts"]),
                    "user": str(row["user"]),
                    "method": str(row["method"]),
                    "template": str(row["template"]),
                }
                for _, row in hits.iterrows()
            ],
        },
    )


# --- F5 --------------------------------------------------------------------


@saved("Did anyone finally succeed on a path that had only ever denied them?")
def first_success_after_denials(
    events: pd.DataFrame | None = None, min_prior_denials: int = 5
) -> QueryResult:
    """A user's first 200 on a path where every earlier attempt was a 403.

    `min_prior_denials` is the whole difference between a finding and noise.
    Unfiltered, the query also returns a single day-one denial followed by a
    success on a path the user turns out to own, which is an access grant
    landing, not a breach. The rows below the threshold stay in `stats` so the
    choice is visible instead of hidden.
    """
    frame = _events(events)
    resolved = frame[frame["status"].isin([200, 403])].sort_values("line")

    is_success = resolved["status"].eq(200)
    is_denial = resolved["status"].eq(403)
    keys = [resolved["user"], resolved["base"]]
    prior_successes = is_success.groupby(keys).cumsum() - is_success.astype(int)
    prior_denials = is_denial.groupby(keys).cumsum() - is_denial.astype(int)

    flips = resolved[is_success & (prior_successes == 0) & (prior_denials > 0)].copy()
    flips["prior_denials"] = prior_denials[flips.index]

    def describe(row: pd.Series) -> dict:
        attempts = frame[
            (frame["user"] == row["user"]) & (frame["base"] == row["base"])
        ]
        denials = attempts[attempts["status"] == 403]
        return {
            "line": int(row["line"]),
            "user": str(row["user"]),
            "path": str(row["base"]),
            "ts": _iso(row["ts"]),
            "ip": str(row["ip"]),
            "size": int(row["size"]),
            "prior_denials": int(row["prior_denials"]),
            "total_denials": int(len(denials)),
            "denials_after_success": int(len(denials[denials["line"] > row["line"]])),
            "successes_on_path": int(len(attempts[attempts["status"] == 200])),
        }

    all_flips = [describe(row) for _, row in flips.iterrows()]
    kept = [flip for flip in all_flips if flip["prior_denials"] >= min_prior_denials]

    return QueryResult(
        name="first_success_after_denials",
        question=first_success_after_denials.question,  # type: ignore[attr-defined]
        lines=[flip["line"] for flip in kept],
        stats={
            "min_prior_denials": min_prior_denials,
            "flips": kept,
            "flips_below_threshold": [
                flip for flip in all_flips if flip["prior_denials"] < min_prior_denials
            ],
            "total_flips_any_threshold": len(all_flips),
            "user_path_pairs_examined": int(resolved.groupby(["user", "base"]).ngroups),
        },
    )


# --- F6 --------------------------------------------------------------------


@saved("Which HTTP status codes are so rare they name their own events?")
def anomalous_status(
    events: pd.DataFrame | None = None, max_occurrences: int = 5
) -> QueryResult:
    """Statuses occurring fewer than `max_occurrences` times in the file.

    Simpler and stronger than a rare template: a status code that occurs once
    in 180,800 lines needs no model to be surprising.
    """
    frame = _events(events)
    counts = frame["status"].value_counts()
    rare = counts[counts < max_occurrences]

    hits = frame[frame["status"].isin(rare.index)].sort_values("line")

    return QueryResult(
        name="anomalous_status",
        question=anomalous_status.question,  # type: ignore[attr-defined]
        lines=_lines(hits),
        stats={
            "max_occurrences": max_occurrences,
            "status_counts": {str(k): int(v) for k, v in counts.sort_index().items()},
            "rare_statuses": {str(k): int(v) for k, v in rare.sort_index().items()},
            "events": [
                {
                    "line": int(row["line"]),
                    "ts": _iso(row["ts"]),
                    "user": str(row["user"]),
                    "path": str(row["path"]),
                    "status": int(row["status"]),
                    "size": int(row["size"]),
                }
                for _, row in hits.iterrows()
            ],
        },
    )


# --- F7 --------------------------------------------------------------------


@saved("Who touched the forum object that preceded the privileged call?")
def post_attribution(
    events: pd.DataFrame | None = None, window_s: float = 10.0
) -> QueryResult:
    """A successful forum post followed within seconds by a post view.

    A heuristic, and it is labelled as one everywhere it surfaces. The log
    records that a post was accepted; it never records which object the
    creation produced and never records authorship. What it does record is
    that exactly one of 9,081 successful posts is followed within ten seconds
    by its author viewing a post, and that the object he opened is the object
    whose view precedes the only privileged call in the file.
    """
    frame = _events(events)

    posts = (
        frame[(frame["base"] == FORUM_NEW) & (frame["status"] == 302)][
            ["ts", "user", "line", "path"]
        ]
        .sort_values("ts")
        .rename(columns={"line": "post_line"})
    )
    views = (
        frame[frame["template"] == FORUM_VIEW][["ts", "user", "line", "obj_id"]]
        .sort_values("ts")
        .rename(columns={"line": "view_line"})
    )

    paired = pd.merge_asof(
        posts,
        views,
        on="ts",
        by="user",
        direction="forward",
        tolerance=pd.Timedelta(seconds=window_s),
    )
    hits = paired[paired["view_line"].notna()]

    chains = []
    for _, row in hits.iterrows():
        view_line = int(row["view_line"])
        view = frame[frame["line"] == view_line].iloc[0]
        obj_id = int(view["obj_id"])
        history = frame[frame["obj_id"] == obj_id].sort_values("line")
        chains.append(
            {
                "post_line": int(row["post_line"]),
                "post_path": str(row["path"]),
                "view_line": view_line,
                "user": str(row["user"]),
                "obj_id": obj_id,
                "gap_s": float((view["ts"] - row["ts"]).total_seconds()),
                # The object is months older than the incident. The chain puts
                # this user on the object; it does not make him its author,
                # and the case file has to say so out loud.
                "object_first_line": int(history.iloc[0]["line"]),
                "object_first_ts": _iso(history.iloc[0]["ts"]),
                "object_event_count": int(len(history)),
            }
        )

    lines: list[int] = []
    for chain in chains:
        lines.extend([chain["post_line"], chain["view_line"]])

    return QueryResult(
        name="post_attribution",
        question=post_attribution.question,  # type: ignore[attr-defined]
        lines=sorted(lines),
        stats={
            "window_s": window_s,
            "successful_posts_examined": int(len(posts)),
            "chain_count": len(chains),
            "chains": chains,
            # Object IDs are a fixed pool here, so no forum/new call can be
            # tied to a new ID: no new ID ever appears.
            "distinct_obj_ids": int(frame["obj_id"].nunique()),
            "obj_id_range": [int(frame["obj_id"].min()), int(frame["obj_id"].max())],
        },
    )


# --- supporting queries the timeline cites ---------------------------------


@saved("Did a privileged call follow straight after the user opened a post?")
def content_triggered_privileged_action(
    events: pd.DataFrame | None = None, window_s: float = 60.0
) -> QueryResult:
    """An /api/admin/ call preceded within a minute by a forum post view.

    The sequence is the case. A user reading a page cannot, in any ordinary
    application, cause her session to change somebody's role a second later.
    """
    frame = _events(events)
    privileged = frame[frame["template"].str.startswith(PRIVILEGED_PREFIX)].sort_values(
        "line"
    )

    chains = []
    lines: list[int] = []
    for _, action in privileged.iterrows():
        views = frame[
            (frame["user"] == action["user"])
            & (frame["template"] == FORUM_VIEW)
            & (frame["ts"] <= action["ts"])
            & (frame["ts"] >= action["ts"] - pd.Timedelta(seconds=window_s))
        ].sort_values("line")
        if views.empty:
            continue
        view = views.iloc[-1]
        chains.append(
            {
                "view_line": int(view["line"]),
                "action_line": int(action["line"]),
                "user": str(action["user"]),
                "ip": str(action["ip"]),
                "obj_id": int(view["obj_id"]),
                "template": str(action["template"]),
                "gap_s": float((action["ts"] - view["ts"]).total_seconds()),
                "view_ts": _iso(view["ts"]),
                "action_ts": _iso(action["ts"]),
                # The response body is all the log keeps of the grant, and it
                # is too small to hold a name. Measured, not remembered.
                "action_size": int(action["size"]),
            }
        )
        lines.extend([int(view["line"]), int(action["line"])])

    return QueryResult(
        name="content_triggered_privileged_action",
        question=content_triggered_privileged_action.question,  # type: ignore[attr-defined]
        lines=sorted(lines),
        stats={
            "window_s": window_s,
            "privileged_calls": int(len(privileged)),
            "chain_count": len(chains),
            "chains": chains,
        },
    )


@saved("How often was the file denied to this user before he got it?")
def denials_before_exfil(
    events: pd.DataFrame | None = None,
    user: str | None = None,
    path: str | None = None,
) -> QueryResult:
    """Every 403 the exfiltrating user collected on the file he took.

    Defaults to the user and path F5 surfaced, so the two findings can never
    drift apart.
    """
    frame = _events(events)
    if user is None or path is None:
        flips = first_success_after_denials(frame).stats["flips"]
        if not flips:
            return QueryResult(
                name="denials_before_exfil",
                question=denials_before_exfil.question,  # type: ignore[attr-defined]
                lines=[],
                stats={},
            )
        user = user or flips[0]["user"]
        path = path or flips[0]["path"]

    attempts = frame[(frame["user"] == user) & (frame["base"] == path)].sort_values(
        "line"
    )
    successes = attempts[attempts["status"] == 200]
    denials = attempts[attempts["status"] == 403]
    success_line = int(successes.iloc[0]["line"]) if not successes.empty else None
    before = denials[denials["line"] < (success_line or 0)]
    after = denials[denials["line"] > (success_line or 0)]

    # The last denial before the door opened and the first one after it closed
    # again. Both are evidence: the order is the whole point of the count.
    evidence = [int(before.iloc[-1]["line"])] if not before.empty else []
    if not after.empty:
        evidence.append(int(after.iloc[0]["line"]))

    return QueryResult(
        name="denials_before_exfil",
        question=denials_before_exfil.question,  # type: ignore[attr-defined]
        lines=sorted(evidence),
        stats={
            "user": user,
            "path": path,
            "total_denials": int(len(denials)),
            "denials_before_success": int(len(before)),
            "denials_after_success": int(len(after)),
            "successes": int(len(successes)),
            "success_line": success_line,
            "first_denial_line": (
                int(denials.iloc[0]["line"]) if not denials.empty else None
            ),
            "last_denial_before_success_line": (
                int(before.iloc[-1]["line"]) if not before.empty else None
            ),
            "last_denial_before_success_ts": (
                _iso(before.iloc[-1]["ts"]) if not before.empty else None
            ),
            # The door closed again afterwards and no log line records either
            # the grant or the revocation. That gap is unknown U3.
            "first_denial_after_success_line": (
                int(after.iloc[0]["line"]) if not after.empty else None
            ),
            "first_denial_after_success_ts": (
                _iso(after.iloc[0]["ts"]) if not after.empty else None
            ),
        },
    )


@saved("Did the attacker go back to the object after the download?")
def vector_object_edits(
    events: pd.DataFrame | None = None,
    user: str | None = None,
    obj_id: int | None = None,
    after_line: int | None = None,
) -> QueryResult:
    """The attacker's first edit of the vector object after the exfiltration."""
    frame = _events(events)
    if user is None or obj_id is None:
        chains = post_attribution(frame).stats["chains"]
        if not chains:
            return QueryResult(
                name="vector_object_edits",
                question=vector_object_edits.question,  # type: ignore[attr-defined]
                lines=[],
                stats={},
            )
        user = user or chains[0]["user"]
        obj_id = obj_id if obj_id is not None else chains[0]["obj_id"]
    if after_line is None:
        flips = first_success_after_denials(frame).stats["flips"]
        after_line = flips[0]["line"] if flips else 0

    edits = frame[
        (frame["user"] == user)
        & (frame["template"] == FORUM_EDIT)
        & (frame["obj_id"] == obj_id)
        & (frame["line"] > after_line)
    ].sort_values("line")
    first = edits.head(1)
    everyone = frame[(frame["template"] == FORUM_EDIT) & (frame["obj_id"] == obj_id)]

    return QueryResult(
        name="vector_object_edits",
        question=vector_object_edits.question,  # type: ignore[attr-defined]
        lines=_lines(first),
        stats={
            "user": user,
            "obj_id": obj_id,
            "after_line": after_line,
            "edits_after_success": int(len(edits)),
            "first_edit_ts": _iso(first.iloc[0]["ts"]) if not first.empty else None,
            # Editing this object is ordinary in isolation: everybody does it
            # all year. It is evidence only in sequence, which is why it is
            # timeline context and not a finding of its own.
            "edits_by_anyone_overall": int(len(everyone)),
        },
    )


@saved("What did the attacker read next, on a path he was allowed to read?")
def cover_download(
    events: pd.DataFrame | None = None,
    user: str | None = None,
    after_line: int | None = None,
    within_hours: float = 2.0,
) -> QueryResult:
    """The first authorized sensitive read by the attacker after the theft.

    Innocent on its own, which is the point: it is what the same behaviour
    looks like when the file is one he is allowed to have.
    """
    frame = _events(events)
    if user is None or after_line is None:
        flips = first_success_after_denials(frame).stats["flips"]
        if not flips:
            return QueryResult(
                name="cover_download",
                question=cover_download.question,  # type: ignore[attr-defined]
                lines=[],
                stats={},
            )
        user = user or flips[0]["user"]
        after_line = after_line if after_line is not None else flips[0]["line"]

    start = frame[frame["line"] == after_line].iloc[0]["ts"]
    window = frame[
        (frame["user"] == user)
        & (frame["line"] > after_line)
        & (frame["ts"] <= start + pd.Timedelta(hours=within_hours))
        & (frame["status"] == 200)
        & (frame["base"].str.contains(SENSITIVE_PREFIXES, regex=True))
    ].sort_values("line")
    first = window.head(1)

    return QueryResult(
        name="cover_download",
        question=cover_download.question,  # type: ignore[attr-defined]
        lines=_lines(first),
        stats={
            "user": user,
            "after_line": after_line,
            "within_hours": within_hours,
            "path": str(first.iloc[0]["base"]) if not first.empty else None,
            "ts": _iso(first.iloc[0]["ts"]) if not first.empty else None,
            "minutes_after_exfil": (
                round(float((first.iloc[0]["ts"] - start).total_seconds() / 60), 1)
                if not first.empty
                else None
            ),
            "reads_in_window": int(len(window)),
        },
    )


@saved("Does the log record any mechanism by which a failing login succeeds?")
def credential_mechanism_gap(events: pd.DataFrame | None = None) -> QueryResult:
    """The gap between the last failed login and the first successful one.

    This grounds unknown U1 in a measurement rather than a shrug. An access
    log records the outcome of authentication and never the mechanism: there
    is no password reset, token issue or credential endpoint anywhere in the
    27 templates, so nothing in this file can say how the guessing stopped
    being guessing.
    """
    frame = _events(events)
    burst = auth_fail_burst(frame)
    if not burst.stats.get("bursts"):
        return QueryResult(
            name="credential_mechanism_gap",
            question=credential_mechanism_gap.question,  # type: ignore[attr-defined]
            lines=[],
            stats={},
        )

    last = burst.stats["bursts"][-1]
    user, ip = last["user"], last["ip"]
    last_failure_line = last["lines"][-1]
    last_failure_ts = frame[frame["line"] == last_failure_line].iloc[0]["ts"]

    success = frame[
        (frame["user"] == user)
        & (frame["ip"] == ip)
        & (frame["status"] == 200)
        & (frame["line"] > last_failure_line)
    ].sort_values("line")
    first_success = success.head(1)
    success_line = int(first_success.iloc[0]["line"]) if not first_success.empty else None

    between = frame[
        (frame["ip"] == ip)
        & (frame["line"] > last_failure_line)
        & (frame["line"] < (success_line or 0))
    ]

    templates = sorted(frame["template"].unique().tolist())
    credential_hints = ("reset", "password", "passwd", "token", "credential", "mfa")
    credential_templates = [
        template
        for template in templates
        if any(hint in template.lower() for hint in credential_hints)
    ]

    return QueryResult(
        name="credential_mechanism_gap",
        question=credential_mechanism_gap.question,  # type: ignore[attr-defined]
        lines=[last_failure_line] + ([success_line] if success_line else []),
        stats={
            "user": user,
            "ip": ip,
            "last_failure_line": last_failure_line,
            "last_failure_ts": _iso(last_failure_ts),
            "first_success_line": success_line,
            "first_success_ts": (
                _iso(first_success.iloc[0]["ts"]) if not first_success.empty else None
            ),
            "hours_between": (
                round(
                    float(
                        (first_success.iloc[0]["ts"] - last_failure_ts).total_seconds()
                        / 3600
                    ),
                    1,
                )
                if not first_success.empty
                else None
            ),
            "requests_from_ip_between": int(len(between)),
            "users_on_ip_between": sorted(between["user"].dropna().unique().tolist()),
            "template_count": len(templates),
            # Nothing to reset a password with, anywhere in the file.
            "credential_templates": credential_templates,
        },
    )


# --- dismissed leads -------------------------------------------------------


@saved("Is confidential access after hours unusual here?")
def offhours_confidential_access(
    events: pd.DataFrame | None = None,
    start_hour: int = OFF_HOURS_START,
    end_hour: int = OFF_HOURS_END,
) -> QueryResult:
    """Successful confidential reads inside one stated window, 20:00 to 06:00.

    The lead dies on its own evidence, though not the way it is usually put.
    Off-hours confidential reads are rare here rather than routine: a handful
    out of thousands. What kills the lead is whose they are. Every off-hours
    read outside the incident belongs to a reader entitled to that file
    working from their own machine, and the one that does belong to the
    incident is already named by the IP binding, so an hour-based rule buys
    only false positives.
    """
    frame = _events(events)
    confidential = frame[
        frame["base"].str.contains(CONFIDENTIAL_MARKER) & (frame["status"] == 200)
    ]
    hour = confidential["ts"].dt.hour
    off_hours = confidential[(hour >= start_hour) | (hour < end_hour)].sort_values("line")

    owner = baseline_ip_by_user(frame)
    own_machine = off_hours[off_hours["ip"] == off_hours["user"].map(owner)]
    foreign = off_hours[off_hours["ip"] != off_hours["user"].map(owner)]

    return QueryResult(
        name="offhours_confidential_access",
        question=offhours_confidential_access.question,  # type: ignore[attr-defined]
        lines=_lines(own_machine),
        stats={
            "window": f"{start_hour:02d}:00-{end_hour:02d}:00",
            "confidential_successes": int(len(confidential)),
            "off_hours_successes": int(len(off_hours)),
            # The share is the whole answer to "is this routine?", so measure
            # it here rather than letting anyone eyeball the two counts.
            "off_hours_share_pct": (
                round(100 * len(off_hours) / len(confidential), 2)
                if len(confidential)
                else 0.0
            ),
            "from_own_baseline_ip": int(len(own_machine)),
            "from_a_foreign_ip": int(len(foreign)),
            # The lead as people actually phrase it is "after midnight", so
            # answer that narrower question too rather than around it.
            "after_midnight": int((own_machine["ts"].dt.hour < end_hour).sum()),
            "after_midnight_examples": [
                {
                    "line": int(row["line"]),
                    "ts": _iso(row["ts"]),
                    "user": str(row["user"]),
                    "ip": str(row["ip"]),
                    "path": str(row["base"]),
                }
                for _, row in own_machine[
                    own_machine["ts"].dt.hour < end_hour
                ].iterrows()
            ],
            # Which file each after-midnight read touched. The lead is almost
            # always asked about the stolen zip specifically, and the answer
            # there is one read, not five.
            "after_midnight_by_path": {
                str(path): int(count)
                for path, count in own_machine[own_machine["ts"].dt.hour < end_hour][
                    "base"
                ]
                .value_counts()
                .items()
            },
            "foreign_lines": _lines(foreign),
            "users": sorted(own_machine["user"].dropna().unique().tolist()),
            "examples": [
                {
                    "line": int(row["line"]),
                    "ts": _iso(row["ts"]),
                    "user": str(row["user"]),
                    "ip": str(row["ip"]),
                    "path": str(row["base"]),
                }
                for _, row in own_machine.iterrows()
            ],
        },
    )


@saved("Do the hundreds of other failed logins have any structure?")
def scattered_auth_failures(events: pd.DataFrame | None = None) -> QueryResult:
    """The 401s outside the two bursts: every user, every month, alone.

    The returned lines are a sample, not the set. The claim is about a
    distribution, and the drill-down should show a handful of representative
    lines rather than a haystack.
    """
    frame = _events(events)
    burst = auth_fail_burst(frame)
    failures = frame[frame["status"] == 401].sort_values("line")
    isolated = failures[~failures["line"].isin(burst.lines)]

    per_user = isolated.groupby("user").size()
    per_month = (
        isolated["ts"].dt.tz_localize(None).dt.to_period("M").value_counts().sort_index()
    )

    return QueryResult(
        name="scattered_auth_failures",
        question=scattered_auth_failures.question,  # type: ignore[attr-defined]
        lines=_lines(isolated.head(10)),
        stats={
            "total_401": int(len(failures)),
            "isolated_401": int(len(isolated)),
            "in_burst_401": int(len(burst.lines)),
            "users": int(isolated["user"].nunique()),
            "months": int(len(per_month)),
            "per_user_min": int(per_user.min()),
            "per_user_max": int(per_user.max()),
            "per_month": {str(k): int(v) for k, v in per_month.items()},
            "paths": sorted(isolated["base"].unique().tolist()),
            "sample_lines": _lines(isolated.head(10)),
            "min_gap_s_outside_bursts": burst.stats["min_gap_s_outside_bursts"],
        },
    )


@saved("Is the volume of 403s itself a signal?")
def routine_denials(events: pd.DataFrame | None = None) -> QueryResult:
    """Denials spread over every user, every sensitive path, every month.

    The access model denies constantly by design, so volume says nothing. The
    signal is a denial that turns into a success, which is F5, and which
    happens once.
    """
    frame = _events(events)
    denials = frame[frame["status"] == 403].sort_values("line")
    per_user = denials.groupby("user").size()
    per_path = denials.groupby("base").size()
    flips = first_success_after_denials(frame)

    return QueryResult(
        name="routine_denials",
        question=routine_denials.question,  # type: ignore[attr-defined]
        lines=_lines(denials.head(10)),
        stats={
            "total_403": int(len(denials)),
            "users": int(denials["user"].nunique()),
            "paths": int(denials["base"].nunique()),
            "days": int(denials["ts"].dt.date.nunique()),
            "per_user_min": int(per_user.min()),
            "per_user_max": int(per_user.max()),
            "per_path_min": int(per_path.min()),
            "per_path_max": int(per_path.max()),
            "denial_to_success_flips": flips.stats["total_flips_any_threshold"],
            "flips_above_threshold": len(flips.stats["flips"]),
            "sample_lines": _lines(denials.head(10)),
        },
    )


def run(name: str, events: pd.DataFrame | None = None, **kwargs) -> QueryResult:
    """Re-run a saved query by the name the case file cites."""
    short = name.split(".")[-1]
    if short not in QUERIES:
        raise KeyError(f"no saved query named {name!r}; have {sorted(QUERIES)}")
    return QUERIES[short](events, **kwargs)


def run_all(events: pd.DataFrame | None = None) -> dict[str, QueryResult]:
    frame = _events(events)
    return {name: query(frame) for name, query in QUERIES.items()}


def main() -> None:
    frame = load_events()
    for result in run_all(frame).values():
        print(f"\n=== {result.qualified_name}")
        print(f"    {result.question}")
        print(f"    lines  {result.lines}")
        print(f"    stats  {json.dumps(result.stats, default=str)[:700]}")


if __name__ == "__main__":
    main()
