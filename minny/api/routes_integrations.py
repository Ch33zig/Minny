"""Integration routes (track D), mounted under /api by the app.

Routes are declared without the /api prefix because `minny.api.app` adds it.

    GET  /api/integrations/status      per capability, never one boolean
    POST /api/integrations/test        fires one Slack message
    POST /api/integrations/gmail/sync  bounded queries, upserts the store
    GET  /api/evidence/email?ids=      section 11 objects, max 50
    POST /api/integrations/github/pr   a review for an accepted rule

Every handler here is wrapped. Nothing a vendor does, and nothing a missing
credential does, may reach a client as a stack trace or a 500, and none of it
may change the case file, the detector, the incidents or the metrics. A
capability that is not connected reports `mock` and the demo continues.

The distinction that runs through all of it: **delivery status is not
detection status**. Slack refusing a message says nothing about whether an
incident was found, so the two are reported separately and the UI shows them
separately.

Shapes: docs/handoff/00-CONTRACTS.md sections 11 and 12.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Body, Query
from fastapi.responses import JSONResponse

from minny.integrations import config, gmail_evidence, github_pr, slack, store

logger = logging.getLogger("minny.api")

router = APIRouter(tags=["integrations"])

# Contracts section 12: the evidence lookup is a drill-down, not a dump.
MAX_EVIDENCE_IDS = 50


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status, content={"error": {"code": code, "message": message}}
    )


def _degraded(code: str, message: str, **extra) -> dict:
    """A soft failure: a 200 that says plainly that nothing happened.

    A vendor being unreachable is an expected state of this system rather
    than a client error, and turning it into a non-200 would make a UI that
    is meant to keep rendering start showing a failure panel instead.
    """
    return {"state": config.ERROR, "ok": False, "error_code": code, "message": message, **extra}


@router.get("/integrations/status")
def integrations_status():
    """One record per capability, plus the mailbox policy and delivery log.

    Never a single connected flag. Gmail read and Gmail send are separate
    grants and Slack can be down while GitHub is fine, so the caller gets
    four independent states and decides what to draw.
    """
    try:
        capabilities = []
        for cap in config.CAPABILITIES:
            record = config.describe(cap)
            delivery = store.last_delivery(cap.id)
            if delivery and delivery.get("state") == config.ERROR:
                record["state"] = config.ERROR
            record["last_delivery"] = delivery
            capabilities.append(record)

        try:
            mailbox = gmail_evidence.public_summary()
        except Exception as exc:  # noqa: BLE001 - the mailbox is never required
            logger.warning("mailbox summary unavailable: %s", exc)
            mailbox = {"error": {"code": "mailbox_unavailable", "message": str(exc)}}

        return {
            "mode": config.requested_mode(),
            "capabilities": capabilities,
            "mailbox": mailbox,
            "destinations": {
                "base_url": config.base_url(),
                "slack_channel": slack.channel(),
                "github": github_pr.repo(),
            },
            "deliveries": store.deliveries(limit=10),
            "note": (
                "Delivery status is reported apart from detection. An incident "
                "is found whether or not a vendor accepted a message about it."
            ),
        }
    except Exception as exc:  # noqa: BLE001 - status itself never fails
        logger.exception("integration status failed")
        return {
            "mode": config.AUTO,
            "capabilities": [],
            "mailbox": {},
            "destinations": {},
            "deliveries": [],
            "error": {"code": "status_unavailable", "message": str(exc)},
        }


@router.post("/integrations/test")
def integrations_test(payload: dict = Body(default=None)):
    """Fire one Slack message and report what happened.

    With no body it sends a clearly labelled connection test. With
    `{"incident_id": "..."}` it sends the real alert for that incident, which
    exercises the path that matters rather than a demo path beside it: the
    same assembly, the same egress check, and the same refusal to post
    anything that is not high severity.
    """
    incident_id = (payload or {}).get("incident_id") if isinstance(payload, dict) else None
    try:
        if incident_id:
            incident = store.load_incident(str(incident_id))
            if incident is None:
                return _error(404, "unknown_incident", f"no incident {incident_id}")
            delivery = slack.post_incident(incident)
        else:
            delivery = slack.test_message()
    except Exception as exc:  # noqa: BLE001 - a test never breaks the app
        logger.warning("slack test failed: %s", exc)
        delivery = _degraded("slack_test_failed", str(exc), capability=config.SLACK_POST.id)
    return {"delivery": delivery, "detection_unaffected": True}


@router.post("/integrations/gmail/sync")
def gmail_sync(payload: dict = Body(default=None)):
    """Run the bounded queries and upsert `data/email_evidence.json`.

    The response is the report, including the exact query strings that were
    used, so the bound is inspectable rather than promised.
    """
    incident_id = (payload or {}).get("incident_id") if isinstance(payload, dict) else None
    try:
        report = gmail_evidence.sync(incident_id)
    except Exception as exc:  # noqa: BLE001 - the mailbox never breaks a request
        logger.warning("gmail sync failed: %s", exc)
        return {
            "counts": {"stored": 0, "linked": 0},
            "messages": [],
            "queries": [],
            "written": False,
            "source_mode": config.ERROR,
            "error": {"code": "gmail_sync_failed", "message": str(exc)},
        }

    # The store itself is what the evidence route serves. The sync response
    # carries the counts and the policy, and the messages so a caller can see
    # what landed without a second request.
    return report


@router.get("/evidence/email")
def evidence_email(
    ids: str = Query(default="", description="e.g. gmail:18f2c9a1b4d7,gmail:..."),
    lines: str = Query(default="", description="log line numbers, for corroboration"),
):
    """Resolve evidence ids to the section 11 objects, max 50.

    `lines` is an additive selector: it returns the stored messages already
    pinned to those log lines. The linking happened during the sync and is
    recorded in `linked_lines`, so this reads a decision rather than making
    one, and the case file can show corroboration without every view
    re-implementing the rules.
    """
    wanted = [token.strip() for token in ids.split(",") if token.strip()]
    line_tokens = [token.strip() for token in lines.split(",") if token.strip()]

    if not wanted and not line_tokens:
        return _error(
            400, "missing_ids", "Pass ?ids= with evidence ids, or ?lines= with line numbers."
        )
    if len(wanted) > MAX_EVIDENCE_IDS or len(line_tokens) > MAX_EVIDENCE_IDS:
        return _error(
            400,
            "too_many_ids",
            f"The limit is {MAX_EVIDENCE_IDS} per request.",
        )

    try:
        numbers = [int(token) for token in line_tokens]
    except ValueError:
        return _error(
            400, "invalid_lines", f"lines must be comma-separated integers, got {lines!r}"
        )

    try:
        found = list(gmail_evidence.resolve(wanted, limit=MAX_EVIDENCE_IDS)) if wanted else []
        if numbers:
            seen = {message["evidence_id"] for message in found}
            for message in gmail_evidence.by_lines(numbers, limit=MAX_EVIDENCE_IDS):
                if message["evidence_id"] not in seen:
                    found.append(message)
    except Exception as exc:  # noqa: BLE001 - corroboration is never required
        # An unreadable mailbox store hides the corroboration strip. It does
        # not fail the claim the strip sat under.
        logger.warning("email evidence lookup failed: %s", exc)
        return []

    return found[:MAX_EVIDENCE_IDS]


@router.post("/integrations/github/pr")
def github_pull_request(payload: dict = Body(default=None)):
    """Open a review for an accepted rule, or return the body it would post."""
    rule_id = None
    if isinstance(payload, dict):
        rule_id = payload.get("rule_id") or payload.get("id")
    if not rule_id:
        return _error(400, "missing_rule_id", "Pass {\"rule_id\": \"R003\"}.")

    try:
        artifact = github_pr.open_pull_request(str(rule_id))
    except Exception as exc:  # noqa: BLE001 - a vendor never reaches the client
        logger.warning("github pr failed: %s", exc)
        return _degraded("github_pr_failed", str(exc), rule_id=rule_id)

    code = artifact.get("error_code")
    if code == "unknown_rule":
        return _error(404, code, artifact.get("message") or "no such rule")
    if code == "rule_not_accepted":
        return _error(409, code, artifact.get("message") or "the rule did not pass the gate")

    return artifact
