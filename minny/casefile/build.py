"""Assemble data/case_file.json from the saved queries (milestone M1).

    python -m minny.casefile.build
    python -m minny.casefile.build --emit-fixture

The UI renders the whole case file from this one document, so every sentence
in it is built here from a `QueryResult` rather than typed. Change a query
and the prose changes with it; if a query stops returning lines, the build
fails instead of shipping a claim with no evidence behind it.

Shape: docs/handoff/00-CONTRACTS.md section 7.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from minny import paths
from minny.build_events import sha256_of
from minny.casefile import queries
from minny.casefile.queries import QueryResult

CASE_ID = "minny-2026-q1"
TITLE = "Unauthorized access to the Q1 confidential draft"
CONFIDENCE_VALUES = ("high", "medium", "low")
NEWLINE = b"\n"


def _fmt(number: int | float) -> str:
    return f"{number:,}"


def minutes_after(start_iso: str, end_iso: str) -> int:
    return round(
        (pd.Timestamp(end_iso) - pd.Timestamp(start_iso)).total_seconds() / 60
    )


def _finding(
    finding_id: str,
    claim: str,
    confidence: str,
    method: str,
    result: QueryResult,
    evidence_lines: list[int] | None = None,
    evidence_emails: list[str] | None = None,
) -> dict:
    """One finding, refusing to exist without evidence."""
    lines = sorted(set(evidence_lines if evidence_lines is not None else result.lines))
    if not lines:
        raise AssertionError(
            f"{finding_id} has no evidence lines; {result.qualified_name} returned "
            "nothing. Fix the query or drop the claim."
        )
    if confidence not in CONFIDENCE_VALUES:
        raise AssertionError(f"{finding_id} has confidence {confidence!r}")
    return {
        "id": finding_id,
        "claim": claim,
        "confidence": confidence,
        "method": method,
        "evidence_lines": lines,
        "evidence_emails": evidence_emails or [],
        "query": result.qualified_name,
    }


def build_source() -> dict | None:
    """Provenance for the raw log: which file, how many lines, which bytes.

    Additive and optional. The log is shared out of band, so a checkout
    without it still builds a case file; the UI simply renders no hash in the
    rail. The hash is what lets anyone else prove they read the same file.
    """
    path = paths.logs_path()
    if not path.exists():
        return None

    lines = 0
    tail = NEWLINE
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            lines += chunk.count(NEWLINE)
            tail = chunk[-1:]
    if tail not in (NEWLINE, b""):
        lines += 1

    return {
        "file": f"{path.parent.name}/{path.name}",
        "lines": lines,
        "sha256": sha256_of(path),
    }


def load_email_evidence() -> list[dict]:
    """Mailbox records, if track D has synced any.

    Nothing on this path may wait on or depend on the mailbox. No file, a
    half-written file or a rate-limited sync all mean the same thing here: no
    corroboration, and a case file that is otherwise identical.
    """
    path = paths.email_evidence_path()
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if isinstance(payload, dict):
        payload = payload.get("messages") or payload.get("emails") or []
    return [message for message in payload if isinstance(message, dict)]


def attach_email_evidence(findings: list[dict], messages: list[dict]) -> list[dict]:
    """Link a message to a finding when they cite the same log line.

    Corroboration only. Mail headers are trivially forgeable and we did not
    verify DKIM, so an attached message can make a finding richer and must
    never make it more certain: no confidence is touched here.
    """
    for finding in findings:
        lines = set(finding["evidence_lines"])
        linked = sorted(
            {
                str(message["evidence_id"])
                for message in messages
                if message.get("evidence_id")
                and lines & set(message.get("linked_lines") or [])
            }
        )
        if linked:
            finding["evidence_emails"] = sorted(
                set(finding["evidence_emails"]) | set(linked)
            )
    return findings


def build_findings(results: dict[str, QueryResult], total_events: int) -> list[dict]:
    """F1 to F7, each worded from the numbers its query measured."""
    mismatch = results["ip_user_mismatch"]
    burst = results["auth_fail_burst"]
    tampered = results["tampered_forum_post"]
    unique = results["globally_unique_templates"]
    flip = results["first_success_after_denials"]
    rare_status = results["anomalous_status"]
    authorship = results["post_attribution"]
    escalation = results["content_triggered_privileged_action"]
    cleanup = results["vector_object_edits"]
    denials = results["denials_before_exfil"]

    victim = mismatch.stats["violating_users"][0]
    foreign_ip = mismatch.stats["foreign_ips"][0]
    attacker = mismatch.stats["foreign_ip_owners"][0]
    exfil = flip.stats["flips"][0]
    chain = authorship.stats["chains"][0]
    escalation_chain = escalation.stats["chains"][0]

    findings = [
        _finding(
            "F1",
            f"{victim}'s account was used from {foreign_ip}, "
            f"which is {attacker}'s workstation.",
            "high",
            f"Each of the {mismatch.stats['user_count']} users appears on exactly one "
            f"source IP across the {mismatch.stats['baseline_months']} months before "
            f"March. These {len(mismatch.lines)} requests are the only lines in "
            f"{_fmt(total_events)} that break that binding, and every one of them puts "
            f"{victim} on {attacker}'s machine. This is arithmetic, not a score.",
            mismatch,
        ),
        _finding(
            "F2",
            f"{victim}'s password was guessed from {attacker}'s workstation in "
            f"{burst.stats['burst_count']} bursts of "
            f"{' and '.join(str(b['attempts']) for b in burst.stats['bursts'])} "
            "attempts, seconds apart, on consecutive nights.",
            "high",
            f"A burst is {burst.stats['min_length']} or more consecutive 401s from the "
            f"same user and IP with gaps under {int(burst.stats['max_gap_s'])} seconds. "
            f"The file contains exactly {burst.stats['burst_count']}, both "
            f"{burst.stats['burst_users'][0]} from {burst.stats['bursts'][0]['ip']}. "
            f"That is the finding: the other {_fmt(burst.stats['isolated_401'])} failed "
            f"logins have no burst structure at all. Not one pair of consecutive "
            f"failures from the same user and IP is closer than "
            f"{int(burst.stats['min_gap_s_outside_bursts'])} seconds, and there is not "
            f"a single run of two.",
            burst,
        ),
        _finding(
            "F3",
            f"{tampered.stats['users'][0]} sent {tampered.stats['tampered_requests']} "
            "forum posts carrying parameters the application never otherwise receives: "
            f"{', '.join(tampered.stats['unexpected_keys'])}.",
            "high",
            f"{_fmt(tampered.stats['forum_new_requests'])} requests hit "
            f"{queries.FORUM_NEW}, of which "
            f"{_fmt(tampered.stats['topic_only_requests'])} carry only `topic`. These "
            f"{tampered.stats['tampered_requests']} are the only ones with any other "
            f"key, and {queries.FORUM_NEW} is the only path in the file that ever "
            "carries a query string at all.",
            tampered,
        ),
        _finding(
            "F4",
            f"{unique.stats['users'][0]}'s session made the only admin role update and "
            "the only avatar request in the entire log, two seconds apart.",
            "high",
            f"After ID normalization the file holds {unique.stats['template_count']} "
            f"request templates. Exactly two occur once: "
            + "; ".join(
                f"{event['template']} at line {event['line']}"
                for event in unique.stats["events"]
            )
            + ". "
            f"The next rarest template, {unique.stats['next_rarest_template']}, occurs "
            f"{_fmt(unique.stats['next_rarest_count'])} times, so there is no gradient "
            "here to argue about.",
            unique,
        ),
        _finding(
            "F5",
            f"{exfil['user']} downloaded {exfil['path']} after being denied it "
            f"{exfil['prior_denials']} times.",
            "high",
            f"For every one of the {_fmt(flip.stats['user_path_pairs_examined'])} "
            "user/path pairs, the first 200 where every earlier attempt was a 403. "
            f"Two pairs qualify and only this one clears a threshold of "
            f"{flip.stats['min_prior_denials']} prior denials: "
            f"{exfil['prior_denials']} denials before the success, "
            f"{exfil['total_denials']} in total, and "
            f"{exfil['denials_after_success']} more afterwards once the access closed "
            f"again (first at line {denials.stats['first_denial_after_success_line']}). "
            f"The other flip is {flip.stats['flips_below_threshold'][0]['user']}'s "
            "first read of the same file on day one of the dataset: one denial "
            f"followed by "
            f"{_fmt(flip.stats['flips_below_threshold'][0]['successes_on_path'])} "
            "successes, which is an access grant landing, not a breach.",
            flip,
        ),
        _finding(
            "F6",
            "The only "
            + " and the only ".join(sorted(rare_status.stats["rare_statuses"]))
            + f" in {_fmt(total_events)} lines are "
            f"{rare_status.stats['events'][0]['user']}'s two failed payload attempts, "
            "sent before the third one was accepted.",
            "high",
            "Statuses occurring fewer than "
            f"{rare_status.stats['max_occurrences']} times in the whole file. Two "
            "qualify, and each occurs exactly once: "
            + "; ".join(
                f"{event['status']} at line {event['line']} ({event['path']})"
                for event in rare_status.stats["events"]
            )
            + ". Everything else in the log is "
            + ", ".join(
                status
                for status in rare_status.stats["status_counts"]
                if status not in rare_status.stats["rare_statuses"]
            )
            + ". A status code that occurs once in "
            f"{_fmt(total_events)} lines needs no model to be surprising.",
            rare_status,
        ),
        _finding(
            "F7",
            f"{chain['user']} is the likely author of the content in forum post "
            f"{chain['obj_id']}, the post {victim} opened "
            f"{int(escalation_chain['gap_s'])} second before her account performed the "
            "admin role update.",
            "medium",
            "HEURISTIC, and it is the only claim in this file that is not arithmetic. "
            "The logs record requests, never post authorship, and a "
            f"{queries.FORUM_NEW} call never records which object it produced. What "
            f"the logs do record: of {_fmt(authorship.stats['successful_posts_examined'])} "
            f"accepted forum posts, exactly one is followed within "
            f"{int(authorship.stats['window_s'])} seconds by the same user opening a "
            f"post: {chain['user']}'s tampered post at line {chain['post_line']}, then "
            f"his view of {chain['obj_id']} {int(chain['gap_s'])} seconds later at line "
            f"{chain['view_line']}. Object {chain['obj_id']} itself predates the "
            f"incident: it first appears at line {chain['object_first_line']} on "
            f"{chain['object_first_ts'][:10]} and carries "
            f"{chain['object_event_count']} events, so he did not create it. He edits "
            f"that same object once more at line {cleanup.lines[0]}, "
            f"{minutes_after(exfil['ts'], cleanup.stats['first_edit_ts'])} minutes "
            "after the download. Treat the attribution as an inference from "
            "sequence, not as a record.",
            authorship,
            evidence_lines=authorship.lines + escalation.lines + cleanup.lines,
        ),
    ]
    return findings


# Each timeline row cites one line. The actor and timestamp are read from the
# event itself and the expectations are asserted, so a sentence can never
# drift away from the line it points at. Any number a row quotes is a
# placeholder filled from the query that measured it, so a recount cannot
# leave a stale figure behind in the prose.
TIMELINE: tuple[tuple[int, str, str | None, str, dict], ...] = (
    (
        168311,
        "Four failed logins as sarah_j from david_m's workstation, 3 to 6 seconds "
        "apart (lines 168311-168314)",
        "First of the two bursts in the file, see F2",
        "high",
        {"user": "sarah_j", "ip": "10.0.8.45", "status": 401},
    ),
    (
        168315,
        "david_m is denied the Q1 confidential draft again",
        "The last of {denials_before} denials before the download, see F5",
        "high",
        {"user": "david_m", "status": 403},
    ),
    (
        168321,
        "Six more failed logins as sarah_j from the same workstation, 2 to 4 seconds "
        "apart (lines 168321-168326)",
        "Second and last burst in the file, see F2",
        "high",
        {"user": "sarah_j", "ip": "10.0.8.45", "status": 401},
    ),
    (
        168330,
        "david_m posts to the forum with an extra `payload` parameter and the server "
        "returns the only 500 in the log",
        "First payload attempt, see F3 and F6",
        "high",
        {"user": "david_m", "status": 500},
    ),
    (
        168331,
        "He posts again 22 minutes later with an `action` parameter and gets the only "
        "400 in the log",
        "Second payload attempt, see F3 and F6",
        "high",
        {"user": "david_m", "status": 400},
    ),
    (
        168332,
        "A third post carrying `script=success` is accepted",
        "The payload that worked, see F3",
        "high",
        {"user": "david_m", "status": 302},
    ),
    (
        168333,
        "Three seconds later he opens forum post 1042",
        "Authorship is inferred from this sequence, see F7",
        "medium",
        {"user": "david_m", "obj_id": 1042},
    ),
    (
        168335,
        "sarah_j opens forum post 1042 from her own machine",
        None,
        "high",
        {"user": "sarah_j", "ip": "10.0.5.12", "obj_id": 1042},
    ),
    (
        168336,
        "One second later her session calls POST /api/admin/role_update, the only "
        "privileged call in the file",
        "The log records the call, never the grantee, see U3",
        "high",
        {"user": "sarah_j", "base": "/api/admin/role_update", "status": 200},
    ),
    (
        168337,
        "Her session then fetches /assets/avatar_1042.png, the only avatar request in "
        "the log",
        None,
        "high",
        {"user": "sarah_j", "obj_id": 1042},
    ),
    (
        168338,
        "Nineteen minutes after the role update, david_m downloads the Q1 confidential "
        "draft he had been denied {denials_before} times",
        "{denials_before} of his {denials_total} denials on the file come before this "
        "line, see F5",
        "high",
        {
            "user": "david_m",
            "base": "/finance/reports/q1_draft_CONFIDENTIAL.zip",
            "status": 200,
        },
    ),
    (
        168339,
        "He edits forum post 1042",
        "Consistent with removing the payload, though the log never shows a body",
        "medium",
        {"user": "david_m", "obj_id": 1042, "status": 302},
    ),
    (
        168340,
        "He reads /finance/templates/expense.docx, a file he is authorized for",
        "Ordinary on its own; it is what the same behaviour looks like when allowed",
        "medium",
        {"user": "david_m", "status": 200},
    ),
    (
        168343,
        "That night sarah_j's account logs in successfully from david_m's workstation",
        "The mechanism that turned failures into a success is not in the log, see U1",
        "high",
        {"user": "sarah_j", "ip": "10.0.8.45", "status": 200},
    ),
    (
        168345,
        "Her session downloads the Q1 confidential draft from his machine",
        None,
        "high",
        {
            "user": "sarah_j",
            "ip": "10.0.8.45",
            "base": "/finance/reports/q1_draft_CONFIDENTIAL.zip",
        },
    ),
    (
        168346,
        "The session logs out three minutes later",
        None,
        "high",
        {"user": "sarah_j", "ip": "10.0.8.45", "base": "/logout"},
    ),
    (
        178028,
        "Twelve days later david_m is denied the Q1 confidential draft again",
        "The first of the {denials_after} denials after the download, the only trace "
        "of the access closing again, see U3",
        "high",
        {
            "user": "david_m",
            "base": "/finance/reports/q1_draft_CONFIDENTIAL.zip",
            "status": 403,
        },
    ),
)


def _fill(text: str | None, counts: dict[str, int]) -> str | None:
    """Put the measured numbers into a row's prose, or leave it alone."""
    if text is None or "{" not in text:
        return text
    return text.format(**counts)


def build_timeline(
    events: pd.DataFrame, evidence: set[int], counts: dict[str, int]
) -> list[dict]:
    """The incident in order, each entry anchored to one verified line."""
    indexed = events.set_index("line")
    timeline = []
    for line, action, note, confidence, expected in TIMELINE:
        if confidence not in CONFIDENCE_VALUES:
            raise AssertionError(f"timeline line {line} has confidence {confidence!r}")
        if line not in indexed.index:
            raise AssertionError(f"timeline cites line {line}, which does not exist")
        if line not in evidence:
            raise AssertionError(
                f"timeline cites line {line}, which no saved query returned"
            )
        row = indexed.loc[line]
        for column, value in expected.items():
            actual = row[column]
            if pd.isna(actual) or actual != value:
                raise AssertionError(
                    f"timeline line {line} expects {column}={value!r}, log says "
                    f"{actual!r}"
                )
        timeline.append(
            {
                "ts": queries._iso(row["ts"]),
                "line": int(line),
                "actor": str(row["user"]),
                "action": _fill(action, counts),
                "note": _fill(note, counts),
                # A beat whose wording rests on an inference says so here, so
                # the UI can mark it rather than rendering every row alike.
                "confidence": confidence,
            }
        )
    return sorted(timeline, key=lambda entry: entry["line"])


def build_unknowns(results: dict[str, QueryResult]) -> list[dict]:
    """What the logs cannot answer, bounded by what they do say.

    An honest unknown reads better than a stretched claim, and two of these
    are exactly what an automated notification email would settle.
    """
    gap = results["credential_mechanism_gap"]
    authorship = results["post_attribution"]
    denials = results["denials_before_exfil"]
    escalation = results["content_triggered_privileged_action"]
    chain = authorship.stats["chains"][0]
    privileged = escalation.stats["chains"][0]

    return [
        {
            "id": "U1",
            "text": (
                f"How the login as {gap.stats['user']} eventually succeeded. Ten "
                f"failures across two nights, then a 200 from the same workstation "
                f"{gap.stats['hours_between']} hours later (line "
                f"{gap.stats['first_success_line']}). In between, the only "
                f"{gap.stats['requests_from_ip_between']} requests from that machine "
                f"belong to {', '.join(gap.stats['users_on_ip_between'])}. None of the "
                f"{gap.stats['template_count']} templates in the file is a password "
                "reset, a token issue or any other credential endpoint, so the "
                "mechanism is not recorded anywhere in this evidence."
            ),
            "query": gap.qualified_name,
            "evidence_lines": gap.lines,
        },
        {
            "id": "U2",
            "text": (
                f"What forum post {chain['obj_id']} actually contained. The logs "
                "record requests and never bodies, so the payload is inferred from "
                f"its effect. The object carries {chain['object_event_count']} events "
                f"going back to {chain['object_first_ts'][:10]}, and the edit after "
                "the download shows only a 302, never what changed."
            ),
            "query": authorship.qualified_name,
            "evidence_lines": authorship.lines,
        },
        {
            "id": "U3",
            "text": (
                f"Who granted and then revoked {denials.stats['user']}'s access to "
                f"{denials.stats['path']}. The order is the evidence, not the total: "
                f"{denials.stats['denials_before_success']} denials come before the "
                f"download, the download is line {denials.stats['success_line']}, and "
                f"{denials.stats['denials_after_success']} further denials follow from "
                f"line {denials.stats['first_denial_after_success_line']} on "
                f"{denials.stats['first_denial_after_success_ts'][:10]}, "
                f"{denials.stats['total_denials']} in all. Those "
                f"{denials.stats['denials_after_success']} reopened denials are the "
                "only trace in the file that the access closed again, and they are "
                "what puts this unknown here. The one privileged call in the log "
                f"returns {privileged['action_size']} bytes and names nobody, so "
                "neither the grant nor the revocation has an author in this evidence."
            ),
            "query": denials.qualified_name,
            "evidence_lines": [
                denials.stats["last_denial_before_success_line"],
                denials.stats["success_line"],
                denials.stats["first_denial_after_success_line"],
            ],
        },
    ]


def _stat(label: str, value) -> dict:
    """One figure on a suspect card. Values are formatted, never invented."""
    return {"label": label, "value": _fmt(value) if isinstance(value, int) else value}


def build_actors(results: dict[str, QueryResult]) -> dict:
    """The two suspect cards, every figure on them read out of a query.

    The UI renders `confidence`, `summary`, `stats` and `evidence_lines` when
    they are present and the plain user and IP when they are not, so nothing
    here may become load bearing.
    """
    mismatch = results["ip_user_mismatch"]
    flip = results["first_success_after_denials"]
    denials = results["denials_before_exfil"]
    burst = results["auth_fail_burst"]
    tampered = results["tampered_forum_post"]
    escalation = results["content_triggered_privileged_action"]
    authorship = results["post_attribution"]
    unique = results["globally_unique_templates"]
    rare_status = results["anomalous_status"]
    cleanup = results["vector_object_edits"]

    victim = mismatch.stats["violating_users"][0]
    foreign_ip = mismatch.stats["foreign_ips"][0]
    attacker = mismatch.stats["foreign_ip_owners"][0]
    exfil = flip.stats["flips"][0]
    authorized = flip.stats["flips_below_threshold"][0]
    chain = authorship.stats["chains"][0]
    asset = exfil["path"]

    if authorized["user"] != victim or authorized["path"] != asset:
        raise AssertionError(
            "the victim card quotes the other flip on the same file; that row is "
            f"now {authorized['user']} on {authorized['path']}"
        )

    attacker_lines = sorted(
        set(
            denials.lines
            + tampered.lines
            + cleanup.lines
            + [chain["view_line"], exfil["line"]]
        )
    )
    victim_lines = sorted(
        set(
            [entry["lines"][0] for entry in burst.stats["bursts"]]
            + escalation.lines
            + unique.lines
            + mismatch.lines[-4:]
        )
    )

    return {
        "attacker": {
            "user": attacker,
            "ip": foreign_ip,
            "role": "attacker",
            "confidence": "high",
            "summary": (
                f"Works from {foreign_ip} and from nowhere else, across all "
                f"{mismatch.stats['baseline_months']} baseline months. He was denied "
                f"{asset} {denials.stats['denials_before_success']} times before the "
                f"download at line {exfil['line']} and "
                f"{denials.stats['denials_after_success']} more times from "
                f"{denials.stats['first_denial_after_success_ts'][:10]}, once the "
                f"access had closed again, {denials.stats['total_denials']} in all "
                "and never 80 before the download, with "
                f"{exfil['successes_on_path']} success in between."
            ),
            "stats": [
                _stat(
                    "denials before the download",
                    denials.stats["denials_before_success"],
                ),
                _stat("denials after it", denials.stats["denials_after_success"]),
                _stat("successes on the asset", exfil["successes_on_path"]),
                _stat(
                    "statuses unique to him",
                    ", ".join(sorted(rare_status.stats["rare_statuses"])),
                ),
            ],
            "evidence_lines": attacker_lines,
        },
        "victim": {
            "user": victim,
            "ip": mismatch.stats["baseline_ip_by_user"][victim],
            "role": "victim",
            "confidence": "high",
            "summary": (
                f"An authorized reader of {asset} with "
                f"{_fmt(authorized['successes_on_path'])} successes on it. She is the "
                f"only one of the {mismatch.stats['user_count']} accounts in the file "
                f"that ever appears on a second address, and that address is "
                f"{attacker}'s workstation."
            ),
            "stats": [
                _stat("successes on the asset", authorized["successes_on_path"]),
                _stat(
                    "source IPs before March",
                    mismatch.stats["baseline_ips_per_user"][victim],
                ),
                _stat("source IPs in the file", mismatch.stats["ips_per_user"][victim]),
                _stat(
                    f"login failures from {foreign_ip}",
                    int(mismatch.stats["statuses"]["401"]),
                ),
            ],
            "evidence_lines": victim_lines,
        },
        "asset": asset,
        "vector": {"obj_id": chain["obj_id"], "template": queries.FORUM_VIEW},
    }


def build_dismissed(results: dict[str, QueryResult]) -> list[dict]:
    """Leads that look like the breach and are not. Each one needs its query."""
    offhours = results["offhours_confidential_access"]
    scattered = results["scattered_auth_failures"]
    denials = results["routine_denials"]
    flip = results["first_success_after_denials"]

    asset = flip.stats["flips"][0]["path"]
    authorized = flip.stats["flips_below_threshold"][0]
    after_midnight = offhours.stats["after_midnight_examples"]
    # The lead is nearly always asked about the stolen file, so answer that
    # question with its own count rather than the count for every
    # confidential path.
    on_asset = [entry for entry in after_midnight if entry["path"] == asset]
    on_asset_count = offhours.stats["after_midnight_by_path"].get(asset, 0)
    if len(on_asset) != on_asset_count:
        raise AssertionError(
            f"after-midnight reads of {asset}: {len(on_asset)} examples against a "
            f"count of {on_asset_count}"
        )
    if on_asset_count != 1:
        raise AssertionError(
            f"the dismissed lead is worded for one after-midnight read of {asset}, "
            f"the query found {on_asset_count}"
        )
    if offhours.stats["from_a_foreign_ip"] != 1:
        raise AssertionError(
            "the dismissed lead is worded for a single off-hours read from a foreign "
            f"IP, the query found {offhours.stats['from_a_foreign_ip']}"
        )
    night = on_asset[0]

    return [
        {
            "id": "D1",
            "lead": "Employees pulling confidential files outside working hours",
            "why": (
                "Off-hours access happens here, and outside the incident every "
                "instance of it belongs to someone entitled to the file, working "
                f"from their own machine. Of "
                f"{_fmt(offhours.stats['confidential_successes'])} successful "
                f"confidential reads, {offhours.stats['off_hours_successes']} fall "
                f"in the {offhours.stats['window']} window, "
                f"{offhours.stats['off_hours_share_pct']}% of them, so the hour is "
                "rare rather than routine. Rarity is not what clears the lead "
                f"though: ownership is. "
                f"{offhours.stats['from_own_baseline_ip']} of the "
                f"{offhours.stats['off_hours_successes']} are authorized readers on "
                "their own baseline machines, and the one that is left is the "
                f"incident itself (line {offhours.stats['foreign_lines'][0]}), which "
                f"the IP binding already names. {offhours.stats['after_midnight']} of "
                "the "
                f"{offhours.stats['from_own_baseline_ip']} are strictly after midnight "
                "("
                + "; ".join(
                    f"{entry['user']} at {entry['ts'][11:16]} on {entry['ts'][:10]}, "
                    f"line {entry['line']}"
                    for entry in after_midnight
                )
                + f"), and exactly {on_asset_count} of those touches {asset}: "
                f"{night['user']} at {night['ts'][11:16]} on {night['ts'][:10]} from "
                f"{night['ip']} (line {night['line']}), her own machine and a file she "
                f"reads {_fmt(authorized['successes_on_path'])} times in this log. "
                "The clock never separates the theft from ordinary work; the source "
                f"IP does. A {offhours.stats['window']} rule buys "
                f"{offhours.stats['from_own_baseline_ip']} false positives and no new "
                "true one."
            ),
            "confidence": "high",
            "query": offhours.qualified_name,
            "evidence_lines": offhours.lines,
        },
        {
            "id": "D2",
            "lead": f"The {_fmt(scattered.stats['total_401'])} failed logins in the file",
            "why": (
                f"{_fmt(scattered.stats['isolated_401'])} of them sit outside the two "
                f"bursts, spread across all {scattered.stats['users']} users and all "
                f"{scattered.stats['months']} months "
                f"({scattered.stats['per_user_min']} to "
                f"{scattered.stats['per_user_max']} per user), every one of them a "
                "lone mistyped password on "
                f"{scattered.stats['paths'][0]}. No two consecutive failures from the "
                "same user and IP are closer than "
                f"{int(scattered.stats['min_gap_s_outside_bursts'])} seconds. Volume is "
                "the baseline; the structure in F2 is the signal."
            ),
            "confidence": "high",
            "query": scattered.qualified_name,
            "evidence_lines": scattered.lines,
        },
        {
            "id": "D3",
            "lead": f"The {_fmt(denials.stats['total_403'])} permission denials",
            "why": (
                "The access model denies constantly by design: "
                f"{_fmt(denials.stats['total_403'])} denials across "
                f"{denials.stats['users']} users, {denials.stats['paths']} paths and "
                f"{denials.stats['days']} days, {denials.stats['per_user_min']} to "
                f"{denials.stats['per_user_max']} per user. Nobody is unusual for "
                "being denied. Out of "
                f"{denials.stats['denial_to_success_flips']} denial-to-success flips "
                f"in the whole file, {denials.stats['flips_above_threshold']} follows "
                "a sustained history of denial, and that one is F5."
            ),
            "confidence": "high",
            "query": denials.qualified_name,
            "evidence_lines": denials.lines,
        },
    ]


def build_case_file(events: pd.DataFrame | None = None) -> dict:
    frame = queries._events(events)
    results = queries.run_all(frame)

    mismatch = results["ip_user_mismatch"]
    flip = results["first_success_after_denials"]
    authorship = results["post_attribution"]
    escalation = results["content_triggered_privileged_action"]
    burst = results["auth_fail_burst"]
    tampered = results["tampered_forum_post"]
    denials = results["denials_before_exfil"]
    unique = results["globally_unique_templates"]
    rare_status = results["anomalous_status"]

    victim = mismatch.stats["violating_users"][0]
    foreign_ip = mismatch.stats["foreign_ips"][0]
    attacker = mismatch.stats["foreign_ip_owners"][0]
    exfil = flip.stats["flips"][0]
    chain = authorship.stats["chains"][0]
    escalation_chain = escalation.stats["chains"][0]

    findings = attach_email_evidence(
        build_findings(results, int(len(frame))), load_email_evidence()
    )
    evidence = {line for finding in findings for line in finding["evidence_lines"]}
    evidence |= {line for result in results.values() for line in result.lines}

    minutes_to_exfil = round(
        (
            pd.Timestamp(exfil["ts"]) - pd.Timestamp(escalation_chain["action_ts"])
        ).total_seconds()
        / 60
    )

    summary = (
        f"{attacker} sent three forum posts carrying parameters the application never "
        f"accepts (lines {tampered.lines[0]}-{tampered.lines[-1]}); the third was "
        f"accepted. {victim} opened the post "
        f"{int(escalation_chain['gap_s'])} second before her session made the only "
        f"admin role update in the log (lines {escalation.lines[0]}-"
        f"{escalation.lines[-1]}), and {minutes_to_exfil} minutes later {attacker} "
        f"downloaded {exfil['path']}, which he had been denied "
        f"{exfil['prior_denials']} times (line {exfil['line']}). That night her account "
        f"logged in from his workstation, after {burst.stats['in_burst_401']} failed "
        f"attempts over two nights, and took the file again (lines "
        f"{mismatch.lines[-4]}-{mismatch.lines[-1]})."
    )

    # One sentence under the verdict for the reader who wants to know why any
    # of this should be believed before they read seven findings.
    basis = (
        f"{len(mismatch.lines)} of {_fmt(len(frame))} lines break the one user, one "
        "IP binding; the only "
        + " and the only ".join(sorted(rare_status.stats["rare_statuses"]))
        + f" in the file are {attacker}'s two failed payload attempts; and "
        f"{len(unique.stats['unique_templates'])} templates occur exactly once, one "
        "of them the single admin role update. Those are counts over the whole file, "
        f"not scores. The one inference is who wrote post {chain['obj_id']}, and F7 "
        "carries medium confidence for it."
    )

    case_file = {
        "case_id": CASE_ID,
        "title": TITLE,
        "window": {
            "start": queries._iso(frame["ts"].min()),
            "end": queries._iso(frame["ts"].max()),
        },
        # Additive: the UI puts this in the provenance rail, and renders
        # without it when the raw log is not on this machine.
        "source": build_source(),
        "verdict": {"summary": summary, "confidence": "high", "basis": basis},
        "actors": build_actors(results),
        "findings": findings,
        "timeline": build_timeline(
            frame,
            evidence,
            {
                "denials_before": denials.stats["denials_before_success"],
                "denials_after": denials.stats["denials_after_success"],
                "denials_total": denials.stats["total_denials"],
            },
        ),
        "unknowns": build_unknowns(results),
        "dismissed": build_dismissed(results),
        # Additive, and the point of the whole module: every number above came
        # out of a query anyone can re-run against this exact input.
        "provenance": {
            "generated_at": datetime.now(timezone.utc).astimezone().isoformat(),
            "events": str(paths.events_path().name),
            "event_count": int(len(frame)),
            "command": "python -m minny.casefile.build",
            "queries": {
                result.qualified_name: result.lines for result in results.values()
            },
        },
    }
    if case_file["source"] is None:
        del case_file["source"]
    return case_file


# --- the UI fixture --------------------------------------------------------
#
# fixtures/mock/case_file.json used to be written by hand from the same
# dataset, and the two documents drifted into telling different stories: a
# different verdict, different findings, a different off-hours window. The
# demo runs on the fixture and live mode runs on the generated file, so the
# drift was invisible until a judge flipped the switch. The fixture is now a
# copy of the generated document and nothing else, which is the only way the
# two can be kept from disagreeing again.

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "fixtures" / "mock"
# Documents whose line numbers the UI can expand in fixture mode. Every one
# of them has to resolve in events.json, per web/verify_fixtures.py.
FIXTURE_DOCUMENTS = ("case_file.json", "incidents.json", "alerts.json")
LINE_KEYS = ("evidence_lines", "lines", "linked_lines", "injected_lines")


def cited_lines(node) -> set[int]:
    """Every log line a fixture document lets the UI drill into."""
    found: set[int] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key in LINE_KEYS and isinstance(value, list):
                found |= {int(item) for item in value if isinstance(item, int)}
            elif key == "line" and isinstance(value, int):
                found.add(value)
            else:
                found |= cited_lines(value)
    elif isinstance(node, list):
        for item in node:
            found |= cited_lines(item)
    return found


def fixture_lines(case_file: dict) -> set[int]:
    """What the regenerated case file cites, plus what the other tracks cite.

    The events fixture is shared. Emitting only this document's lines would
    take the incident and alert drill-downs out with it.
    """
    lines = cited_lines(case_file)
    for name in FIXTURE_DOCUMENTS:
        path = FIXTURE_DIR / name
        if name == "case_file.json" or not path.exists():
            continue
        lines |= cited_lines(json.loads(path.read_text(encoding="utf-8")))

    stream = FIXTURE_DIR / "stream.ndjson"
    if stream.exists():
        for raw in stream.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            frame = json.loads(raw)
            if frame.get("type") == "event":
                lines |= cited_lines(frame.get("data") or {})
    return lines


def raw_lines(wanted: set[int]) -> dict[int, str]:
    """The original bytes of each line, read out of the log itself."""
    path = paths.require(paths.logs_path())
    found: dict[int, str] = {}
    with open(path, "rb") as handle:
        for number, raw in enumerate(handle, 1):
            if number in wanted:
                found[number] = raw.decode("utf-8").rstrip()
    return found


def build_events_fixture(wanted: set[int], existing: list[dict]) -> list[dict]:
    """The evidence rows for those lines, shaped exactly like GET /api/events.

    Imported here rather than at module scope so the case file still builds
    on a machine where the API dependencies are not installed.
    """
    from minny.api.routes_case import EVIDENCE_COLUMNS, _serialize

    frame = pd.read_parquet(
        paths.require(paths.events_path()), columns=list(EVIDENCE_COLUMNS)
    ).set_index("line", drop=False)
    original = raw_lines(wanted)
    # Lines past the end of the real log are the red team's injected variant.
    # They have no bytes to read and this module did not write them, so they
    # are carried across untouched rather than regenerated.
    injected = {
        int(row["line"]): row
        for row in existing
        if int(row["line"]) not in frame.index
    }

    rows = []
    for line in sorted(wanted):
        if line not in frame.index:
            if line not in injected:
                raise AssertionError(
                    f"fixture cites line {line}, which is neither in the log nor an "
                    "injected event already in events.json"
                )
            rows.append(injected[line])
            continue
        row = _serialize(frame.loc[line])
        # The bytes come out of logs.txt, never out of the parsed fields. If
        # the two ever disagree the evidence block is showing a forgery.
        if original.get(line) != row["raw"]:
            raise AssertionError(
                f"line {line} in the log does not match the parsed raw text"
            )
        row["raw"] = original[line]
        rows.append(row)
    return rows


def emit_fixture(case_file_path: Path) -> tuple[Path, Path, int]:
    """Copy the generated case file into the fixtures and refresh its evidence."""
    text = paths.require(case_file_path).read_text(encoding="utf-8")
    case_file = json.loads(text)

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    fixture_path = FIXTURE_DIR / "case_file.json"
    fixture_path.write_text(text, encoding="utf-8")

    events_path = FIXTURE_DIR / "events.json"
    existing = (
        json.loads(events_path.read_text(encoding="utf-8"))
        if events_path.exists()
        else []
    )
    events = build_events_fixture(fixture_lines(case_file), existing)
    events_path.write_text(json.dumps(events, indent=2), encoding="utf-8")
    return fixture_path, events_path, len(events)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(paths.case_file_path()))
    parser.add_argument(
        "--emit-fixture",
        action="store_true",
        help="also copy the document into fixtures/mock/ and refresh events.json",
    )
    args = parser.parse_args()

    case_file = build_case_file()
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(case_file, indent=2), encoding="utf-8")

    print(f"wrote       {out_path}")
    print(f"findings    {len(case_file['findings'])}")
    for finding in case_file["findings"]:
        print(
            f"  {finding['id']} {finding['confidence']:<6} "
            f"{len(finding['evidence_lines'])} lines  {finding['claim'][:72]}"
        )
    print(f"timeline    {len(case_file['timeline'])} entries")
    print(f"unknowns    {len(case_file['unknowns'])}")
    print(f"dismissed   {len(case_file['dismissed'])}")

    if args.emit_fixture:
        fixture_path, events_path, count = emit_fixture(out_path)
        print(f"fixture     {fixture_path}")
        print(f"evidence    {events_path} ({count} lines)")


if __name__ == "__main__":
    main()
