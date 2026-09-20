"""The mailbox rules: what we ask for, what we keep, and what attaches.

Pure functions, no I/O and no vendor. `gmail_evidence` drives them.

Logs answer *what happened*. They are silent on *who authorized it*: line
168336 records a request to `/api/admin/role_update` and an 85 byte response
that names nobody. A permission change notification names the grantee. That
is the entire reason the mailbox is here, and it is also why every rule below
is conservative: an email is corroboration, never a claim on its own.

Four rules carry the weight.

1. **Bounded queries.** Three fixed, app coded searches: a window derived
   from the incident, a sender allowlist, a subject keyword set, a result
   cap. There is no free text query and no path by which model output
   becomes a search string, and there is no full mailbox crawl.
2. **Headers only.** `sanitize` rebuilds each message from an allowlist of
   fields. A body cannot survive it, because a body is never copied across.
3. **Deterministic classification.** An ordered keyword map over the subject,
   then the snippet, then the sender. An LLM may only ever refine `other`
   and may never invent a matched entity, so no model runs in this path.
4. **Entity match AND time proximity.** Both, always. An email that matches
   on time alone attaches to nothing, and `link_basis` records which rules
   fired so the UI can show why a message is attached.

Shapes and rules: docs/handoff/00-CONTRACTS.md section 11.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

# ------------------------------------------------------------------ bounds

# The incident window is widened by this much on each side. Contracts section
# 11: a message outside it is not attached, whatever it says.
WINDOW_PAD_HOURS = 24

# A hard ceiling on the window regardless of what the incident claims, so a
# malformed incident can never turn into a mailbox crawl.
MAX_WINDOW_DAYS = 45

# Per query, per sync.
MAX_RESULTS = 50

SENDER_ALLOWLIST = (
    "no-reply@intranet.example.com",
    "it-notifications@example.com",
    "security@example.com",
)


@dataclass(frozen=True)
class BoundedQuery:
    """One fixed search. Every field is a constant in this file."""

    id: str
    purpose: str
    senders: tuple[str, ...]
    subject_keywords: tuple[str, ...]
    max_results: int = MAX_RESULTS


QUERIES: tuple[BoundedQuery, ...] = (
    BoundedQuery(
        id="permissions",
        purpose="permission changes, access requests, group membership",
        senders=("no-reply@intranet.example.com", "it-notifications@example.com"),
        subject_keywords=(
            "role updated",
            "access request",
            "access granted",
            "access removed",
            "permission",
            "group",
            "membership",
        ),
    ),
    BoundedQuery(
        id="credentials",
        purpose="credential resets and second factor changes",
        senders=("no-reply@intranet.example.com", "it-notifications@example.com"),
        subject_keywords=("password", "credential", "mfa", "token"),
    ),
    BoundedQuery(
        id="exports",
        purpose="data export confirmations and security alerts",
        senders=("no-reply@intranet.example.com", "security@example.com"),
        subject_keywords=(
            "export",
            "download",
            "security alert",
            "suspicious",
            "unusual sign-in",
        ),
    ),
)


def window_for(opened_ts: str, last_ts: str) -> tuple[datetime, datetime]:
    """The incident window widened by 24 hours, clamped to the hard ceiling."""
    start = datetime.fromisoformat(opened_ts)
    end = datetime.fromisoformat(last_ts)
    if end < start:
        start, end = end, start
    start -= timedelta(hours=WINDOW_PAD_HOURS)
    end += timedelta(hours=WINDOW_PAD_HOURS)
    if end - start > timedelta(days=MAX_WINDOW_DAYS):
        start = end - timedelta(days=MAX_WINDOW_DAYS)
    return start, end


def render_query(query: BoundedQuery, start: datetime, end: datetime) -> str:
    """The Gmail search string, assembled only from constants and the window."""
    senders = " OR ".join(query.senders)
    subjects = " OR ".join(f'subject:"{word}"' for word in query.subject_keywords)
    after = start.strftime("%Y/%m/%d")
    before = (end + timedelta(days=1)).strftime("%Y/%m/%d")
    return f"from:({senders}) ({subjects}) after:{after} before:{before}"


def in_bounds(query: BoundedQuery, message: dict, start: datetime, end: datetime) -> bool:
    """The same bound applied locally.

    The live path already asked Gmail for exactly this, and the recorded path
    holds the whole seeded mailbox. Applying the predicate here means the
    bound is enforced by our code in both modes rather than trusted to the
    vendor in one of them.
    """
    sender = str(message.get("from") or "").casefold()
    if not any(allowed.casefold() in sender for allowed in query.senders):
        return False

    subject = str(message.get("subject") or "").casefold()
    if not any(word in subject for word in query.subject_keywords):
        return False

    try:
        ts = datetime.fromisoformat(str(message.get("ts")))
    except (TypeError, ValueError):
        return False
    return start <= ts <= end


# ------------------------------------------------------------------- store

# The only fields that are ever copied out of a message. A body has no entry
# here, which is how "never bodies" is enforced rather than asserted.
KEPT_FIELDS = ("id", "threadId", "ts", "from", "to", "subject", "snippet")

# Anything Gmail might return that carries a body. Counted so the sync can
# report that it dropped them, never stored.
BODY_FIELDS = ("body", "payload", "raw", "parts", "messageText", "htmlBody", "textBody")

# A snippet is a preview, not a body. Truncated so a long preview cannot
# become one by accident.
MAX_SNIPPET_CHARS = 240


def sanitize(message: dict) -> dict:
    """Rebuild a message from the allowlist. Returns headers and a snippet."""
    kept = {field: message.get(field) for field in KEPT_FIELDS}
    to = kept.get("to")
    if isinstance(to, str):
        to = [part.strip() for part in to.split(",") if part.strip()]
    kept["to"] = to or []
    snippet = str(kept.get("snippet") or "")
    kept["snippet"] = snippet[:MAX_SNIPPET_CHARS]
    return kept


def dropped_body_fields(message: dict) -> list[str]:
    return [field for field in BODY_FIELDS if field in message]


# -------------------------------------------------------------- categories

CATEGORIES = (
    "permission_change",
    "access_request",
    "access_revoked",
    "group_membership",
    "credential_reset",
    "data_export",
    "security_alert",
    "other",
)

# Ordered. The first rule that matches wins, which is why revocation sits
# above permission change: "Role updated: david.m removed from" is both, and
# the removal is the more specific fact.
CATEGORY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("access_revoked", ("removed from", "access removed", "revoked", "access revoked")),
    (
        "access_request",
        ("access request", "requested access", "requested read access", "approve or decline"),
    ),
    ("permission_change", ("role updated", "role update", "added to", "permission", "granted")),
    ("group_membership", ("group membership", "membership", "added to the group")),
    ("credential_reset", ("password", "credential", "mfa", "token reset")),
    ("data_export", ("export", "download", "transfer complete")),
    ("security_alert", ("security alert", "suspicious", "unusual sign-in", "new sign-in")),
)

SENDER_CATEGORY = {"security@example.com": "security_alert"}


def classify(message: dict) -> str:
    """Subject first, then snippet, then the sender map. Never a model.

    Contracts section 11 allows an LLM to refine `other` and nothing else.
    None runs here: every category this ships with is reachable from the
    keyword map, and an unreachable one stays `other` rather than becoming a
    guess nobody can re-derive.
    """
    subject = str(message.get("subject") or "").casefold()
    for category, keywords in CATEGORY_RULES:
        if any(word in subject for word in keywords):
            return category

    snippet = str(message.get("snippet") or "").casefold()
    for category, keywords in CATEGORY_RULES:
        if any(word in snippet for word in keywords):
            return category

    sender = str(message.get("from") or "").casefold()
    for address, category in SENDER_CATEGORY.items():
        if address in sender:
            return category
    return "other"


# ---------------------------------------------------------------- entities

# Token characters. `/` is not one, so a path splits into its segments and
# the filename survives whole. `-` is one, so `finance-confidential` stays a
# single token.
_SPLIT = re.compile(r"[^A-Za-z0-9._@-]+")
_TRIM = re.compile(r"^[._@-]+|[._@-]+$")

IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# Which group a confidential area maps to. App coded, per deployment, and it
# is the only way a group name enters the vocabulary.
GROUP_BY_AREA = {
    "finance": "finance-confidential",
    "hr": "hr-confidential",
    "exec": "exec-confidential",
    "it": "it-admins",
}


def tokens(text: str) -> set[str]:
    out = set()
    for piece in _SPLIT.split(text or ""):
        piece = _TRIM.sub("", piece)
        if piece:
            out.add(piece.casefold())
    return out


def normalize_user(token: str) -> str:
    """`david_m`, `david.m` and `david.m@example.com` all become `david_m`.

    Exact on the normalized token, never substring, which is the whole reason
    `davidson.k` does not match `david_m`.
    """
    local = token.split("@", 1)[0]
    return local.replace(".", "_").replace("-", "_").casefold()


def asset_names(asset: str | None) -> set[str]:
    """The filename, and the filename without its extension."""
    if not asset:
        return set()
    base = asset.rstrip("/").rsplit("/", 1)[-1].casefold()
    names = {base}
    if "." in base:
        names.add(base.rsplit(".", 1)[0])
    return {name for name in names if name}


def groups_for(asset: str | None) -> set[str]:
    if not asset:
        return set()
    area = asset.lstrip("/").split("/", 1)[0].casefold()
    group = GROUP_BY_AREA.get(area)
    return {group} if group else set()


@dataclass(frozen=True)
class Vocabulary:
    """The entities an incident puts in play. Nothing else can match."""

    users: frozenset[str]
    assets: frozenset[str]
    groups: frozenset[str]
    ips: frozenset[str]


def vocabulary_for(incident: dict) -> Vocabulary:
    users = set()
    for who in (incident.get("attacker") or {}, incident.get("victim") or {}):
        if who.get("user"):
            users.add(normalize_user(str(who["user"])))
    ips = set()
    for who in (incident.get("attacker") or {}, incident.get("victim") or {}):
        if who.get("ip"):
            ips.add(str(who["ip"]).casefold())
    asset = incident.get("asset")
    return Vocabulary(
        users=frozenset(users),
        assets=frozenset(asset_names(asset)),
        groups=frozenset(groups_for(asset)),
        ips=frozenset(ips),
    )


def match_entities(message: dict, vocab: Vocabulary) -> dict:
    """Which incident entities appear in the headers and the snippet.

    Only the subject, snippet, sender and recipients are read, which is all
    that is stored in the first place.
    """
    haystack = " ".join(
        [
            str(message.get("subject") or ""),
            str(message.get("snippet") or ""),
            str(message.get("from") or ""),
            " ".join(message.get("to") or []),
        ]
    )
    raw = tokens(haystack)
    normalized = {normalize_user(token) for token in raw}

    users = sorted(name for name in vocab.users if name in normalized)
    assets = sorted(name for name in vocab.assets if name in raw)
    groups = sorted(name for name in vocab.groups if name in raw)
    found_ips = set(IPV4.findall(haystack))
    ips = sorted(ip for ip in vocab.ips if ip in {found.casefold() for found in found_ips})
    return {"users": users, "assets": assets, "groups": groups, "ips": ips}


def has_entity_match(matched: dict) -> bool:
    return any(matched.get(key) for key in ("users", "assets", "groups", "ips"))


# ----------------------------------------------------------------- linking

# Tightest first. A message pins itself to log lines only when something sits
# within an hour of it; beyond that it corroborates the incident and names no
# line, which is the honest answer rather than the convenient one.
BUCKETS: tuple[tuple[str, timedelta], ...] = (
    ("time_proximity_60s", timedelta(seconds=60)),
    ("time_proximity_5m", timedelta(minutes=5)),
    ("time_proximity_1h", timedelta(hours=1)),
)

# A corroborating strip is a few lines, not a transcript.
MAX_LINKED_LINES = 3


def nearest_lines(ts: datetime, anchors: list[tuple[int, datetime]]) -> tuple[list[int], str | None]:
    """Log lines inside the tightest bucket that holds any, capped at three."""
    for name, span in BUCKETS:
        inside = [(abs(ts - when), line) for line, when in anchors if abs(ts - when) <= span]
        if inside:
            inside.sort()
            lines = sorted(line for _, line in inside[:MAX_LINKED_LINES])
            return lines, name
    return [], None


def link(
    message: dict,
    matched: dict,
    *,
    window: tuple[datetime, datetime],
    anchors: list[tuple[int, datetime]],
) -> tuple[list[str], list[int]]:
    """Both rules, or nothing. Returns `(link_basis, linked_lines)`."""
    entity = has_entity_match(matched)
    try:
        ts = datetime.fromisoformat(str(message.get("ts")))
    except (TypeError, ValueError):
        return [], []

    start, end = window
    in_window = start <= ts <= end

    # Time on its own is not evidence, and neither is a name on its own.
    if not (entity and in_window):
        return [], []

    lines, bucket = nearest_lines(ts, anchors)
    basis = ["entity_match", bucket or "time_proximity_24h"]
    return basis, lines


def confidence_for(basis: list[str]) -> str:
    """Capped at medium, always.

    Mail headers are trivially forgeable and DKIM was not verified, so an
    attached message is `medium` and an unattached one is `low`. Nothing in
    this module can return `high`.
    """
    return "medium" if basis else "low"
