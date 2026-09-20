"""Alert correlation and role attribution (milestone M3).

Alerts that share an entity inside a rolling 72-hour window collapse into one
incident, per docs/handoff/00-CONTRACTS.md section 6. The entities are the
account, the address, the owner of the address, the object ID of a forum post,
and a target file. The owner edge is the one that does the real work: it is
what connects an alert on the victim's account to alerts on the attacker's own
activity without either of them naming the other.

Every sentence an incident carries is a template filled from alert fields.
An incident may not assert anything that is not in some alert's `value` or
`evidence_lines`, because the answer to "where did that sentence come from"
has to be a field name.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# Alerts within this of each other, sharing an entity, are one story. Three
# days spans the 13-15 March chain from the first failed login to the second
# download with room to spare, and is short enough that two unrelated weeks of
# activity on one account never merge.
CORRELATION_WINDOW = timedelta(hours=72)

# Narrative grouping only. Alerts of the same signal closer together than this
# are one step in the story rather than one step each.
NARRATIVE_LINK_S = 3600

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def _parse_ts(value) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(value)


def _entities(alert: dict) -> set:
    """Everything this alert could share with another one.

    Deliberately narrow. A target file is an entity only when the alert is
    about a file that was taken (S2); treating every template as an asset
    would merge every login in the window into one incident.
    """
    found = set()
    if alert.get("user"):
        found.add(("user", alert["user"]))
    if alert.get("ip"):
        found.add(("ip", alert["ip"]))
    if alert.get("ip_owner"):
        found.add(("user", alert["ip_owner"]))
    if alert.get("obj_id") is not None:
        found.add(("obj", alert["obj_id"]))

    value = alert.get("value") or {}
    if alert.get("signal") == "S2":
        found.add(("asset", value.get("template") or alert.get("template")))
    # The S6 chain names the author of the vector post. That edge is what puts
    # the account that clicked and the account that wrote the bait into the
    # same incident.
    if value.get("vector_author"):
        found.add(("user", value["vector_author"]))
    if value.get("vector_obj_id") is not None:
        found.add(("obj", value["vector_obj_id"]))
    return found


@dataclass
class Cluster:
    incident_id: str
    entities: set = field(default_factory=set)
    alerts: list = field(default_factory=list)
    opened_ts: datetime | None = None
    last_ts: datetime | None = None

    def absorb(self, alert: dict, ts: datetime) -> None:
        self.alerts.append(alert)
        self.entities |= _entities(alert)
        self.opened_ts = ts if self.opened_ts is None else min(self.opened_ts, ts)
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)

    def merge(self, other: "Cluster") -> None:
        self.alerts.extend(other.alerts)
        self.entities |= other.entities
        self.opened_ts = min(self.opened_ts, other.opened_ts)
        self.last_ts = max(self.last_ts, other.last_ts)


def _incident_id(alert: dict) -> str:
    """Stable across runs and across merges.

    Derived from the earliest alert in the cluster, so a merge keeps the ID of
    the older story rather than minting a new one and orphaning whatever the
    UI already rendered.
    """
    seed = f"{alert['ts']}:{','.join(str(n) for n in alert['evidence_lines'])}"
    return "inc_" + hashlib.sha1(seed.encode("utf-8")).hexdigest()[:6]


class Correlator:
    """Streaming union of alerts into incidents."""

    def __init__(self, window: timedelta = CORRELATION_WINDOW):
        self.window = window
        self.clusters: list = []

    def add(self, alert: dict) -> str:
        ts = _parse_ts(alert["ts"])
        entities = _entities(alert)

        live = [
            cluster
            for cluster in self.clusters
            if cluster.last_ts is not None and ts - cluster.last_ts <= self.window
        ]
        matches = [c for c in live if c.entities & entities]

        if not matches:
            cluster = Cluster(incident_id=_incident_id(alert))
            self.clusters.append(cluster)
        else:
            # An alert can bridge two stories that were separate until now, so
            # a match on several clusters is a merge rather than a choice.
            cluster = min(matches, key=lambda c: c.opened_ts)
            for other in matches:
                if other is not cluster:
                    cluster.merge(other)
                    self.clusters.remove(other)

        cluster.absorb(alert, ts)
        alert["incident_id"] = cluster.incident_id
        return cluster.incident_id

    def run(self, alerts) -> list:
        for alert in sorted(alerts, key=lambda a: (_parse_ts(a["ts"]), a["alert_id"])):
            self.add(alert)
        return self.incidents()

    def incidents(self) -> list:
        """Newest first, which is the order the API and the UI want."""
        built = [build_incident(c) for c in self.clusters]
        return sorted(built, key=lambda inc: inc["opened_ts"], reverse=True)


def _resolve_attacker(alerts: list) -> dict:
    """Who drove this.

    Two independent sources. The address owner behind the S1 alerts says whose
    machine the victim's session came from. The S6 chain, via S7, says who
    wrote the content that moved the privileges. When they disagree the S6
    chain wins and confidence drops, because the mechanism is stronger
    evidence than the location, and a confident wrong name is worse on stage
    than an honest hedge.
    """
    s1 = [a for a in alerts if a["signal"] == "S1"]
    s6 = [a for a in alerts if a["signal"] == "S6"]

    owners = Counter(
        a["ip_owner"] for a in s1 if a.get("ip_owner") and a["ip_owner"] != a["user"]
    )
    authors = Counter(
        (a.get("value") or {}).get("vector_author")
        for a in s6
        if (a.get("value") or {}).get("vector_author")
    )

    by_owner = owners.most_common(1)[0][0] if owners else None
    by_author = authors.most_common(1)[0][0] if authors else None

    basis = []
    if by_author:
        basis.extend(["S6", "S7"])
    if by_owner:
        basis.append("S1")

    if by_author and by_owner:
        if by_author == by_owner:
            user, confidence = by_author, "high"
        else:
            user, confidence = by_author, "medium"
    elif by_author:
        user, confidence = by_author, "high"
    elif by_owner:
        # Several distinct owners means the address evidence does not point at
        # one person, so it is a lead rather than an attribution.
        user = by_owner
        confidence = "high" if len(owners) == 1 else "medium"
    else:
        # own_ip_takeover: the session came from an address the baseline
        # cannot attribute. The address is still the lead; the name is not.
        user, confidence = None, "low"

    ip = _attacker_ip(alerts, user)
    return {
        "user": user,
        "ip": ip,
        "confidence": confidence,
        "basis": sorted(set(basis)) or ["S1"],
    }


def _attacker_ip(alerts: list, attacker: str | None) -> str | None:
    if attacker:
        own = Counter(a["ip"] for a in alerts if a.get("user") == attacker)
        if own:
            return own.most_common(1)[0][0]
        owned = Counter(
            a["ip"] for a in alerts if a.get("ip_owner") == attacker and a.get("ip")
        )
        if owned:
            return owned.most_common(1)[0][0]
    unowned = Counter(
        a["ip"]
        for a in alerts
        if a["signal"] == "S1" and not a.get("ip_owner") and a.get("ip")
    )
    return unowned.most_common(1)[0][0] if unowned else None


def _resolve_victim(alerts: list, attacker: str | None) -> dict:
    """Whose access was used.

    The account whose session performed the privileged action, or that was
    logged into from someone else's machine. Same tie-break as the attacker:
    the S6 chain beats the address evidence.
    """
    by_chain = Counter(a["user"] for a in alerts if a["signal"] == "S6" and a["user"])
    by_ip = Counter(a["user"] for a in alerts if a["signal"] == "S1" and a["user"])

    chain_user = by_chain.most_common(1)[0][0] if by_chain else None
    ip_user = by_ip.most_common(1)[0][0] if by_ip else None

    basis = []
    if chain_user:
        basis.append("S6")
    if ip_user:
        basis.append("S1")

    if chain_user and ip_user:
        user = chain_user
        confidence = "high" if chain_user == ip_user else "medium"
    elif chain_user:
        user, confidence = chain_user, "high"
    elif ip_user:
        user, confidence = ip_user, "high"
    else:
        user, confidence = None, "low"

    # An account that escalated itself has no victim, and naming one would be
    # an invented fact.
    if user is not None and user == attacker:
        return {"user": None, "confidence": "low", "basis": sorted(set(basis))}
    return {"user": user, "confidence": confidence, "basis": sorted(set(basis)) or ["S1"]}


def _asset(alerts: list) -> str | None:
    taken = [a for a in alerts if a["signal"] == "S2"]
    if not taken:
        return None
    first = min(taken, key=lambda a: _parse_ts(a["ts"]))
    return (first.get("value") or {}).get("template") or first.get("template")


def _vector(alerts: list) -> dict | None:
    chain = [a for a in alerts if a["signal"] == "S6"]
    if not chain:
        return None
    value = min(chain, key=lambda a: _parse_ts(a["ts"])).get("value") or {}
    return {
        "template": value.get("vector_template"),
        "obj_id": value.get("vector_obj_id"),
    }


def _title(attacker: dict, victim: dict, asset: str | None, vector: dict | None) -> str:
    who = attacker["user"]
    whom = victim["user"]
    if who and whom and vector and asset:
        return (
            f"{who} escalated {whom}'s access through forum post "
            f"{vector['obj_id']} and read {asset}"
        )
    if who and whom and vector:
        return (
            f"{who} escalated {whom}'s access through forum post "
            f"{vector['obj_id']}"
        )
    if who and asset:
        return f"{who} read {asset} after activity the baseline does not explain"
    if who and whom:
        return f"{whom}'s account was used from {who}'s workstation"
    if whom and vector:
        return f"{whom}'s account performed a privileged action after viewing post {vector['obj_id']}"
    if whom:
        return f"Unattributed activity on {whom}'s account"
    return "Unattributed activity the baseline does not explain"


def _group_for_narrative(alerts: list) -> list:
    """One step per signal per episode, ordered by when the episode started."""
    buckets: dict = {}
    for alert in sorted(alerts, key=lambda a: (_parse_ts(a["ts"]), a["alert_id"])):
        ts = _parse_ts(alert["ts"])
        run = buckets.get(alert["signal"])
        if run and (ts - _parse_ts(run[-1][-1]["ts"])).total_seconds() <= NARRATIVE_LINK_S:
            run[-1].append(alert)
        else:
            buckets.setdefault(alert["signal"], []).append([alert])
    groups = [run for runs in buckets.values() for run in runs]
    # Ties on the start time break on the earliest evidence line, so a step
    # whose evidence reaches further back is told first. That puts the S6 chain
    # ahead of the alerts that merely note its consequences.
    return sorted(
        groups,
        key=lambda run: (
            _parse_ts(run[0]["ts"]),
            min(line for a in run for line in a["evidence_lines"]),
            run[0]["signal"],
        ),
    )


def _summarize(run: list) -> str:
    """Aggregate a run of same-signal alerts, or reuse the single explanation.

    A one-alert run already carries a template-generated sentence, so reusing
    it keeps one wording for the same fact everywhere it appears.
    """
    if len(run) == 1:
        return run[0]["explanation"]

    first = run[0]
    count = len(run)
    signal = first["signal"]
    user = first.get("user") or "An unauthenticated session"

    if signal == "S1":
        owner = first.get("ip_owner")
        tail = f", which belongs to {owner}" if owner else ", an address with no baseline owner"
        return f"{user} made {count} requests from {first['ip']}{tail}."
    if signal == "S3":
        failures = sum((a.get("value") or {}).get("failures", 0) for a in run)
        return (
            f"{user} produced {count} bursts of authentication failures from "
            f"{first['ip']}, {failures} failures in total."
        )
    if signal == "S4":
        templates = sorted({a["template"] for a in run})
        return (
            f"{user} requested {count} templates the account had never used: "
            f"{', '.join(templates)}."
        )
    if signal == "S5":
        params = sorted(
            {
                name
                for a in run
                for name in (a.get("value") or {}).get("unexpected_params", [])
            }
        )
        return (
            f"{user} sent {count} requests to {first['template']} carrying "
            f"parameters the baseline never records: {', '.join(params)}."
        )
    if signal == "S8":
        codes = sorted({str((a.get("value") or {}).get("status")) for a in run})
        return (
            f"{count} requests returned status codes the baseline window never "
            f"produced: {', '.join(codes)}."
        )
    return f"{count} {first['signal_name']} alerts on {user}."


def _narrative(alerts: list) -> list:
    steps = []
    for run in _group_for_narrative(alerts):
        lines = sorted({line for a in run for line in a["evidence_lines"]})
        steps.append({"ts": run[0]["ts"], "text": _summarize(run), "lines": lines})
    return steps


def build_incident(cluster: Cluster) -> dict:
    alerts = sorted(
        cluster.alerts, key=lambda a: (_parse_ts(a["ts"]), a["alert_id"])
    )
    attacker = _resolve_attacker(alerts)
    victim = _resolve_victim(alerts, attacker["user"])
    asset = _asset(alerts)
    vector = _vector(alerts)
    severity = max(
        (a["severity"] for a in alerts), key=lambda s: SEVERITY_ORDER.get(s, 0)
    )
    synthetic = [a for a in alerts if a.get("synthetic")]
    variant_ids = sorted({a["variant_id"] for a in synthetic if a.get("variant_id")})

    return {
        "incident_id": cluster.incident_id,
        "opened_ts": alerts[0]["ts"],
        "last_ts": alerts[-1]["ts"],
        "severity": severity,
        "status": "open",
        "title": _title(attacker, victim, asset, vector),
        "attacker": attacker,
        "victim": victim,
        "asset": asset,
        "vector": vector,
        "narrative": _narrative(alerts),
        "alerts": [a["alert_id"] for a in alerts],
        "evidence_lines": sorted({n for a in alerts for n in a["evidence_lines"]}),
        # Filled by the track that owns the mailbox. No signal reads email, so
        # an incident is complete and reproducible without it.
        "evidence_emails": [],
        "labels": {
            "synthetic": bool(synthetic),
            "variant_id": variant_ids[0] if variant_ids else None,
        },
    }


def correlate(alerts) -> list:
    return Correlator().run(alerts)
