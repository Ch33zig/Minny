"""Detection signals S1 to S8 (milestone M3).

Every signal is a pure function of ``(event, baselines, state)`` that returns
zero or more alerts in the shape of docs/handoff/00-CONTRACTS.md section 5.
Nothing here reads the mailbox, the case file, or any other track's output:
an alert has to be reproducible from events.parquet and baselines.json alone,
because that is what makes the false-positive count mean anything.

Two rules hold across all of them.

Explanations are templates filled from the same fields that appear in
``value`` and ``evidence_lines``. A sentence a judge reads must be traceable
to a field, not to a model, so no signal writes a number it did not compute.

The hour histogram in the baseline is never consulted. Legitimate off-hours
access is everywhere in this dataset, including an authorised reader pulling
the confidential zip after midnight from her own address, and a signal that
fires on her turns the demo into an argument about false positives.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field

from minny.baselines.model import Baselines
from minny.detect.events import DetectEvent

SIGNAL_NAMES = {
    "S1": "ip_mismatch",
    "S2": "first_success_on_denied",
    "S3": "auth_fail_burst",
    "S4": "novel_template",
    "S5": "unexpected_params",
    "S6": "content_triggered_privileged_action",
    "S7": "post_authorship",
    "S8": "anomalous_status",
}

FORUM_VIEW = "/intranet/forum/view/{id}"
FORUM_NEW = "/intranet/forum/new"

# S3. Three failures inside thirty seconds from one host. The fitted window
# never shows more than one failure in any thirty-second span from any user on
# any address, so this threshold has two whole failures of headroom and still
# produces zero baseline hits. Walking under it is the entire point of the red
# team's slow_guess operator.
AUTH_FAIL_THRESHOLD = 3
AUTH_FAIL_WINDOW_S = 30

# S6. A human reading a forum post and then deliberately navigating to an admin
# endpoint does not do it in five seconds. Below this, the request is a
# consequence of rendering the page rather than of a decision to make it.
PRIVILEGED_AFTER_VIEW_S = 5

# S7. Posting returns a 302 that does not name the object it created, so this
# links an account to a post by nothing stronger than "submitted, then opened
# that post seconds later". Ten seconds is the redirect-and-render budget.
#
# It is deliberately NOT authorship. In this dataset the linked object is a
# seven-month-old thread that all ten accounts read and edit, so "created by"
# would be false. What the timing supports is presence at the vector, which is
# why this signal only ever supports an S6 alert and never raises one itself.
AUTHORSHIP_WINDOW_S = 10


def _alert_id(signal: str, lines) -> str:
    """Deterministic, so a replay produces the same IDs every time.

    C's evaluation diffs alert sets across runs and D's UI keys rows on this,
    so a random ID would make both of them lie about what changed.
    """
    seed = f"{signal}:{','.join(str(line) for line in lines)}"
    return "a_" + hashlib.sha1(seed.encode("utf-8")).hexdigest()[:6]


def _alert(
    signal: str,
    event: DetectEvent,
    severity: str,
    value: dict,
    explanation: str,
    evidence_lines=None,
    ip_owner: str | None = None,
    obj_id: int | None = None,
) -> dict:
    lines = sorted(set(evidence_lines or [event.line]))
    return {
        "alert_id": _alert_id(signal, lines),
        "ts": event.ts.isoformat(),
        "signal": signal,
        "signal_name": SIGNAL_NAMES[signal],
        "severity": severity,
        "user": event.user,
        "ip": event.ip,
        "ip_owner": ip_owner,
        "template": event.template,
        "obj_id": event.obj_id if obj_id is None else obj_id,
        "value": value,
        "evidence_lines": lines,
        "explanation": explanation,
        # Claimed by the correlator, never by the signal.
        "incident_id": None,
    }


def _account(user: str | None) -> str:
    return user if user else "an unauthenticated session"


@dataclass
class PostAuthorship:
    """What S7 knows about who created a forum post."""

    obj_id: int
    user: str
    post_line: int
    view_line: int
    gap_s: float


@dataclass
class RollingState:
    """Everything the signals need that a single event does not carry.

    Bounded by construction: the auth-failure deques are trimmed to the S3
    window and the per-user maps hold one entry each, so memory does not grow
    with the length of the replay.
    """

    auth_fails: dict = field(default_factory=lambda: defaultdict(deque))
    unbaselined: set = field(default_factory=set)
    last_view: dict = field(default_factory=dict)
    last_post: dict = field(default_factory=dict)
    post_author: dict = field(default_factory=dict)
    authorships: list = field(default_factory=list)

    def observe(self, event: DetectEvent) -> None:
        """Fold the event into the rolling state before the signals read it.

        Order matters and is deliberate: S3 has to count the failure it is
        looking at, while S6 and S7 only ever look backwards at a *different*
        event, so folding first is safe for them.
        """
        if event.status == 401:
            window = self.auth_fails[(event.user, event.ip)]
            window.append((event.ts, event.line))
            while (
                window
                and (event.ts - window[0][0]).total_seconds() > AUTH_FAIL_WINDOW_S
            ):
                window.popleft()

        if event.user is None:
            return

        if event.template == FORUM_NEW and event.status == 302:
            self.last_post[event.user] = (event.ts, event.line)
        elif event.template == FORUM_VIEW and event.obj_id is not None:
            self._record_authorship(event)
            self.last_view[event.user] = (event.ts, event.obj_id, event.line)

    def _record_authorship(self, event: DetectEvent) -> None:
        """S7. Emits no alert; it is attribution material for the correlator.

        The log records a 302 on /intranet/forum/new with no object ID, so the
        only thing tying an author to a post is that the author reads it
        immediately after creating it. First writer wins: a later reader of the
        same post is a reader, not the author.
        """
        posted = self.last_post.get(event.user)
        if posted is None or event.obj_id in self.post_author:
            return
        gap = (event.ts - posted[0]).total_seconds()
        if 0 <= gap <= AUTHORSHIP_WINDOW_S:
            record = PostAuthorship(
                obj_id=event.obj_id,
                user=event.user,
                post_line=posted[1],
                view_line=event.line,
                gap_s=round(gap, 1),
            )
            self.post_author[event.obj_id] = record
            self.authorships.append(record)

    def failures_in_window(self, event: DetectEvent) -> deque:
        return self.auth_fails.get((event.user, event.ip), deque())


def s1_ip_mismatch(event, baselines, state) -> list:
    """The address is not one this account has ever used.

    In 180,800 lines there is exactly one violation of the user-to-address
    binding, and it is the victim's account on the attacker's workstation.
    This is arithmetic, not a heuristic.
    """
    if event.user is None:
        return []
    known = baselines.user(event.user).ips

    if not known:
        # An account the fitted window never saw has no binding to violate, so
        # the finding is the account itself. Reported once rather than on every
        # request, because the alternative is one alert per page load for a new
        # joiner and a stream nobody reads.
        if event.user in state.unbaselined:
            return []
        state.unbaselined.add(event.user)
        value = {
            "known_ips": [],
            "observed_ip": event.ip,
            "months_observed": 0,
            "ip_owner": baselines.owner_of(event.ip),
        }
        explanation = (
            f"{event.user} used {event.ip}. The baseline window contains no "
            f"activity for that account at all."
        )
        return [
            _alert("S1", event, "medium", value, explanation,
                   ip_owner=value["ip_owner"])
        ]

    if event.ip in known:
        return []

    owner = baselines.owner_of(event.ip)
    months = baselines.user(event.user).months_observed
    value = {
        "known_ips": sorted(known),
        "observed_ip": event.ip,
        "months_observed": months,
        "ip_owner": owner,
    }
    if owner and owner != event.user:
        severity = "high"
        explanation = (
            f"{event.user} used {event.ip}, which belongs to {owner}. "
            f"That account has used only {', '.join(sorted(known))} across "
            f"{months} months of baseline traffic."
        )
    else:
        # C's own_ip_takeover operator produces exactly this case, so an
        # unowned address is a lower-confidence answer rather than an
        # exception.
        severity = "medium"
        explanation = (
            f"{event.user} used {event.ip}, an address with no owner in the "
            f"baseline. That account has used only {', '.join(sorted(known))} "
            f"across {months} months of baseline traffic."
        )
    return [_alert("S1", event, severity, value, explanation, ip_owner=owner)]


def s2_first_success_on_denied(event, baselines, state) -> list:
    """A 200 on something the baseline only ever refused this account."""
    if event.user is None or event.status != 200:
        return []
    profile = baselines.user(event.user)
    if event.template not in profile.denied_paths:
        return []

    denials = profile.denied_counts.get(event.template, 0)
    value = {
        "template": event.template,
        "baseline_denials": denials,
        "baseline_successes": 0,
    }
    explanation = (
        f"{event.user} received 200 on {event.template}. The baseline window "
        f"refused that account {denials} times on this path and records no "
        f"successful request."
    )
    return [_alert("S2", event, "high", value, explanation)]


def s3_auth_fail_burst(event, baselines, state) -> list:
    """Repeated authentication failures from one host in one short window.

    Fires on the transition across the threshold rather than on every failure
    after it, so a burst of ten produces one alert carrying the count instead
    of eight alerts carrying the same fact.
    """
    if event.status != 401:
        return []
    window = state.failures_in_window(event)
    if len(window) != AUTH_FAIL_THRESHOLD:
        return []

    lines = [line for _ts, line in window]
    span = round((window[-1][0] - window[0][0]).total_seconds(), 1)
    known = baselines.user(event.user).ips
    foreign = bool(known) and event.ip not in known
    owner = baselines.owner_of(event.ip)
    baseline_worst = baselines.user(event.user).auth_fail.get(
        f"max_in_{AUTH_FAIL_WINDOW_S}s", 0
    )
    value = {
        "failures": len(window),
        "window_s": span,
        "threshold": AUTH_FAIL_THRESHOLD,
        "baseline_max_in_window": baseline_worst,
        "ip_is_known_for_user": not foreign,
    }
    explanation = (
        f"{_account(event.user)} failed to authenticate {len(window)} times "
        f"from {event.ip} within {span} seconds. The baseline never shows more "
        f"than {baseline_worst} failure(s) for that account in any "
        f"{AUTH_FAIL_WINDOW_S}-second window."
    )
    # A burst from the account's own machine is a forgotten password. A burst
    # from somebody else's machine is a different claim, so S1's condition is
    # re-evaluated here rather than the two alerts being stitched together.
    severity = "high" if foreign else "medium"
    return [
        _alert("S3", event, severity, value, explanation, evidence_lines=lines,
               ip_owner=owner if foreign else None)
    ]


def s4_novel_template(event, baselines, state) -> list:
    """A template this account has never requested.

    Keyed on the normalised template and never on `base`: post and avatar IDs
    are already collapsed by the parser, and working on the raw path would fire
    on every forum view of a new post and drown the stream.
    """
    if event.user is None:
        return []
    profile = baselines.user(event.user)
    if not profile.templates_seen or event.template in profile.templates_seen:
        return []

    global_freq = baselines.frequency(event.template)
    value = {
        "template": event.template,
        "user_template_count": 0,
        "global_baseline_count": global_freq,
        "user_templates_known": len(profile.templates_seen),
    }
    if global_freq == 0:
        severity = "high"
        explanation = (
            f"{event.user} requested {event.template}, a template no account "
            f"used anywhere in the baseline window."
        )
    else:
        severity = "medium"
        explanation = (
            f"{event.user} requested {event.template} for the first time. "
            f"Other accounts used it {global_freq} times in the baseline "
            f"window; this account used {len(profile.templates_seen)} other "
            f"templates and never this one."
        )
    return [_alert("S4", event, severity, value, explanation)]


def s5_unexpected_params(event, baselines, state) -> list:
    """Query parameters the baseline never saw on this template."""
    sent = set(event.query)
    if not sent:
        return []
    known = baselines.known_params(event.template)
    unexpected = sorted(sent - known)
    if not unexpected:
        return []

    value = {
        "unexpected_params": unexpected,
        "sent_params": sorted(sent),
        "baseline_params": sorted(known),
        "template": event.template,
    }
    explanation = (
        f"{_account(event.user)} sent the parameter(s) "
        f"{', '.join(unexpected)} to {event.template}. The baseline records "
        f"only {', '.join(sorted(known)) or 'no parameters'} on that template."
    )
    return [_alert("S5", event, "medium", value, explanation)]


def s6_content_triggered_privileged_action(event, baselines, state) -> list:
    """A privileged request moments after the same account read a forum post.

    This is the mechanism rather than an anomaly. Any single piece of it is
    arguable: people do view posts, and an admin endpoint does get called. The
    finding is the ordering and the gap, and it is the only signal here that
    explains *how* one account's privileges moved rather than noting *that*
    something looked odd.

    The vector post's author comes from S7 and is carried in `value`, so the
    correlator can name the attacker without inventing anything.
    """
    if event.user is None:
        return []
    if not baselines.is_privileged(event.template, event.method, event.status):
        return []
    viewed = state.last_view.get(event.user)
    if viewed is None:
        return []

    view_ts, obj_id, view_line = viewed
    gap = (event.ts - view_ts).total_seconds()
    if not 0 <= gap <= PRIVILEGED_AFTER_VIEW_S:
        return []

    authorship = state.post_author.get(obj_id)
    lines = [view_line, event.line]
    if authorship:
        lines.extend([authorship.post_line, authorship.view_line])

    value = {
        "vector_template": FORUM_VIEW,
        "vector_obj_id": obj_id,
        "vector_line": view_line,
        "privileged_template": event.template,
        "gap_s": round(gap, 1),
        "window_s": PRIVILEGED_AFTER_VIEW_S,
        "vector_author": authorship.user if authorship else None,
        "vector_author_lines": (
            [authorship.post_line, authorship.view_line] if authorship else []
        ),
    }
    explanation = (
        f"{event.user} viewed forum post {obj_id} and {round(gap, 1)} second(s) "
        f"later the same account requested {event.template}, a privileged "
        f"endpoint."
    )
    if authorship:
        explanation += (
            f" {authorship.user} submitted a post and opened {obj_id} "
            f"{authorship.gap_s} second(s) later, which places that account at "
            f"the vector immediately beforehand. The log does not record which "
            f"object a submission created, so this is association, not "
            f"authorship."
        )
    return [
        _alert(
            "S6",
            event,
            "high",
            value,
            explanation,
            evidence_lines=lines,
            obj_id=obj_id,
        )
    ]


def s8_anomalous_status(event, baselines, state) -> list:
    """A status code the application essentially never returns.

    Simpler and stronger than a rare template: 400 and 500 occur once each in
    180,800 lines and both are failed payload attempts. A status the baseline
    never produced is the application telling you it was asked something it
    was not built to answer.
    """
    count = baselines.status_count(event.status)
    if count >= baselines.rare_status_n:
        return []

    value = {
        "status": event.status,
        "baseline_count": count,
        "threshold": baselines.rare_status_n,
        "path": event.path,
    }
    explanation = (
        f"{event.path} returned {event.status}. That status occurs {count} "
        f"times in the {baselines.document.get('event_count', 0)} events of "
        f"the baseline window, below the threshold of {baselines.rare_status_n}."
    )
    return [_alert("S8", event, "high", value, explanation)]


# S7 is deliberately absent: it emits no alert and runs inside RollingState.
SIGNALS = (
    s1_ip_mismatch,
    s2_first_success_on_denied,
    s3_auth_fail_burst,
    s4_novel_template,
    s5_unexpected_params,
    s6_content_triggered_privileged_action,
    s8_anomalous_status,
)


class Detector:
    """Streams events through every signal and hands back alerts.

    Stateful only through `RollingState`, so the same instance can be fed a
    replay, a live tail, or the red team's injection queue without knowing
    which is which.
    """

    def __init__(self, baselines: Baselines, state: RollingState | None = None):
        self.baselines = baselines
        self.state = state if state is not None else RollingState()

    def feed(self, event: DetectEvent) -> list:
        self.state.observe(event)
        alerts: list = []
        for signal in SIGNALS:
            alerts.extend(signal(event, self.baselines, self.state))
        return alerts

    def run(self, events) -> list:
        alerts: list = []
        for event in events:
            alerts.extend(self.feed(event))
        return alerts
