"""The dataset facts every red-team module is allowed to use (milestone M4).

Everything a variant is built from — users, IPs, forum post IDs, topics,
sensitive targets, response sizes, and the real log lines used as rendering
templates — is read from the artifacts A produced, never hardcoded from the
brief. The brief was wrong about the incident date and four paths; the data
was not. See docs/handoff/GROUND-TRUTH.md.

The planner's enums come from here, which is what keeps an LLM's parameter
choices inside the dataset's own vocabulary.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import lru_cache
from statistics import median

import pandas as pd

from minny import paths
from minny.parser import Event, normalize_template, parse_line

# The real incident, from GROUND-TRUTH.md. Excluded from the benign template
# pool wherever a benign alternative exists, so synthetic lines are cloned
# from ordinary traffic rather than from the attack we are trying to re-run.
INCIDENT_LINES = frozenset(
    [*range(168311, 168315), 168315, *range(168321, 168327), *range(168330, 168341),
     *range(168343, 168347)]
)

CANONICAL_ATTACKER = "david_m"
CANONICAL_VICTIM = "sarah_j"
CANONICAL_TARGET = "/finance/reports/q1_draft_CONFIDENTIAL.zip"

LOGIN_PATH = "/api/auth/login"
LOGOUT_PATH = "/logout"
DASHBOARD_PATH = "/dashboard"
FORUM_NEW_PATH = "/intranet/forum/new"
FORUM_VIEW_TEMPLATE = "/intranet/forum/view/{id}"
FORUM_EDIT_TEMPLATE = "/intranet/forum/edit/{id}"
AVATAR_TEMPLATE = "/assets/avatar_{id}.png"
PRIVILEGED_PATH = "/api/admin/role_update"


@dataclass(frozen=True)
class Catalog:
    """Read-only view of the dataset, shared by the planner and renderer."""

    users: tuple[str, ...]
    user_ip: dict[str, str]
    ip_owner: dict[str, str]
    forum_post_ids: tuple[int, ...]
    forum_topics: tuple[str, ...]
    targets: dict[str, dict]
    # One real line per (template, status), kept parsed so the renderer can
    # inherit method and protocol rather than guess them.
    line_templates: dict[tuple[str, int], Event]

    def authorized(self, target: str) -> tuple[str, ...]:
        return tuple(self.targets[target]["authorized"])

    def denied(self, target: str) -> tuple[str, ...]:
        return tuple(self.targets[target]["denied"])

    def confidential_targets(self) -> tuple[str, ...]:
        """Targets worth stealing: confidential, and someone is shut out.

        A file nobody is denied cannot carry a first-success-on-denied step,
        so it is not a coherent target for the families that need one.
        """
        return tuple(
            path
            for path, meta in sorted(self.targets.items())
            if meta["confidential"] and meta["authorized"] and meta["denied"]
        )

    def is_known_ip(self, ip: str) -> bool:
        return ip in self.ip_owner


def load_access_matrix() -> dict:
    path = paths.require(paths.access_matrix_path())
    return json.loads(path.read_text(encoding="utf-8"))


def load_size_table() -> dict:
    path = paths.require(paths.size_table_path())
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_catalog() -> Catalog:
    """Build the catalog from events.parquet plus A's access matrix."""
    events_path = paths.require(paths.events_path())
    frame = pd.read_parquet(
        events_path,
        columns=["line", "raw", "ip", "user", "base", "status", "template", "obj_id"],
    )

    # Modal IP per user, and modal user per IP. Modal rather than unique on
    # purpose: sarah_j appears on david_m's host twelve times and that single
    # anomaly must not make her IP ambiguous to the planner.
    by_user: dict[str, Counter] = defaultdict(Counter)
    by_ip: dict[str, Counter] = defaultdict(Counter)
    for ip, user in zip(frame["ip"], frame["user"]):
        if user is None:
            continue
        by_user[user][ip] += 1
        by_ip[ip][user] += 1

    user_ip = {user: counts.most_common(1)[0][0] for user, counts in by_user.items()}
    ip_owner = {ip: counts.most_common(1)[0][0] for ip, counts in by_ip.items()}

    forum = frame[frame["template"] == FORUM_VIEW_TEMPLATE]
    post_ids = tuple(sorted(int(v) for v in forum["obj_id"].dropna().unique()))

    topics = _forum_topics(frame)
    line_templates = _line_templates(frame)

    matrix = load_access_matrix()
    return Catalog(
        users=tuple(sorted(user_ip)),
        user_ip=user_ip,
        ip_owner=ip_owner,
        forum_post_ids=post_ids,
        forum_topics=topics,
        targets=matrix["paths"],
        line_templates=line_templates,
    )


def _forum_topics(frame: pd.DataFrame) -> tuple[str, ...]:
    """The twelve real `?topic=` values, read off the raw lines.

    Read from `raw` rather than the parsed query map because the map column
    round-trips through parquet as a list of pairs on some pyarrow versions,
    and a silently empty topic list would make every rendered post identical.
    """
    topics: Counter = Counter()
    posts = frame[(frame["base"] == FORUM_NEW_PATH)]
    for raw, line in zip(posts["raw"], posts["line"]):
        if int(line) in INCIDENT_LINES:
            continue
        event = parse_line(int(line), raw)
        topic = event.query.get("topic")
        if topic:
            topics[topic] += 1
    return tuple(sorted(topics))


def _line_templates(frame: pd.DataFrame) -> dict[tuple[str, int], Event]:
    """One real line per (template, status), preferring benign traffic.

    The renderer overwrites ip, user, ts, path, status and size and inherits
    everything else. Two of the shapes we need — the admin role update and
    the avatar fetch — occur exactly once in 180,800 lines and both of those
    occurrences are the incident, so for those the fallback is the only
    option. Everywhere else a benign line wins.
    """
    chosen: dict[tuple[str, int], Event] = {}
    fallback: dict[tuple[str, int], Event] = {}

    for line, raw, template, status in zip(
        frame["line"], frame["raw"], frame["template"], frame["status"]
    ):
        key = (str(template), int(status))
        if key in chosen:
            continue
        event = parse_line(int(line), raw)
        if int(line) in INCIDENT_LINES:
            fallback.setdefault(key, event)
        else:
            chosen[key] = event

    for key, event in fallback.items():
        chosen.setdefault(key, event)
    return chosen


def template_of(path_or_base: str) -> str:
    """Normalize a base path to its template, ignoring any query string."""
    base = path_or_base.split("?", 1)[0]
    template, _ = normalize_template(base)
    return template


def merge_sizes(values: list[int]) -> list[int]:
    """[min, median, max] over observed sizes, the shape size_table uses."""
    ordered = sorted(values)
    return [ordered[0], int(median(ordered)), ordered[-1]]
