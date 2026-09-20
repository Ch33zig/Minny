"""Slack alerting on a high severity incident.

What goes to Slack is the plain English explanation the incident already
carries, plus a Minny link. What does not go to Slack is evidence: no raw log
line, no mailbox subject, no snippet, no address. Somebody entitled to the
evidence follows the link and reads it inside Minny; the channel itself holds
nothing a source record could be reconstructed from.

The message is assembled field by field from an allowlist of incident fields
and then passed through `egress.check` before it is handed to the adapter.
The allowlist is the real control and the check is the tripwire.

Delivery status is recorded separately from detection. The incident was found
by the detector reading events.parquet; whether Slack accepted a message
about it is a fact about Slack. The UI shows the two independently and the
demo continues either way.

Tool slug: SLACK_CHAT_POST_MESSAGE, 04-COMPOSIO.md section 6.
"""

from __future__ import annotations

import os

from minny.integrations import client, config, egress, store

# How many narrative beats go into the message. Enough to tell the story,
# short enough that a channel stays readable.
MAX_BEATS = 3

DEFAULT_CHANNEL = "#minny-soc"


def channel() -> str:
    """The destination, from stored policy and never from model output."""
    return os.environ.get("MINNY_SLACK_CHANNEL") or DEFAULT_CHANNEL


def incident_url(incident_id: str) -> str:
    return f"{config.base_url()}/#monitor?incident={incident_id}"


def build_message(incident: dict) -> str:
    """The exact text that is posted, built only from allowlisted fields.

    Fields used: severity, title, narrative text, attacker user, victim user,
    asset, the count of evidence lines, the synthetic label, and the Minny
    link. `evidence_lines` contributes its length and never its contents.
    """
    incident_id = str(incident.get("incident_id") or "unknown")
    severity = str(incident.get("severity") or "unknown").upper()
    labels = incident.get("labels") or {}

    lines: list[str] = []
    if labels.get("synthetic"):
        variant = labels.get("variant_id") or "unlabelled"
        lines.append(
            f"[Minny] SYNTHETIC VARIANT {variant}, injected by the red team. "
            f"Not a real incident."
        )
    lines.append(f"[Minny] {severity} severity incident {incident_id}")

    title = incident.get("title")
    if title:
        lines.append(str(title))

    for beat in (incident.get("narrative") or [])[:MAX_BEATS]:
        text = beat.get("text")
        if text:
            lines.append(f"  {text}")

    attacker = (incident.get("attacker") or {}).get("user")
    victim = (incident.get("victim") or {}).get("user")
    asset = incident.get("asset")
    facts = []
    if attacker:
        facts.append(f"attacker {attacker}")
    if victim:
        facts.append(f"account used {victim}")
    if asset:
        facts.append(f"asset {asset}")
    if facts:
        lines.append(", ".join(facts))

    count = len(incident.get("evidence_lines") or [])
    mail = len(incident.get("evidence_emails") or [])
    evidence = f"{count} log lines behind this"
    if mail:
        evidence += f", {mail} mailbox records corroborating"
    lines.append(f"{evidence}. Evidence stays in Minny: {incident_url(incident_id)}")

    return "\n".join(lines)


def post_incident(incident: dict, *, force: bool = False):
    """Post one alert. Returns a delivery record and never raises.

    `force` posts regardless of severity, which is what the test endpoint
    uses. Ordinary alerting is high severity only, because a channel that
    fires on everything is a channel nobody reads.
    """
    incident_id = str(incident.get("incident_id") or "unknown")
    severity = str(incident.get("severity") or "").lower()

    if not force and severity != "high":
        return store.record_delivery(
            {
                "capability": config.SLACK_POST.id,
                "target": incident_id,
                "state": "skipped",
                "ok": True,
                "message": f"severity is {severity or 'unset'}, Slack alerts are high only",
            }
        )

    try:
        text = build_message(incident)
        egress.check(text, store=store.read_email_store())
    except egress.EgressRefused as refused:
        # The message is dropped, the incident is untouched. This is the one
        # outcome where we would rather say nothing than say too much.
        return store.record_delivery(
            {
                "capability": config.SLACK_POST.id,
                "target": incident_id,
                "state": config.ERROR,
                "ok": False,
                "error_code": f"egress_refused:{refused.reason}",
                "message": (
                    "the assembled message carried a source record and was not "
                    "posted. Detection is unaffected."
                ),
            }
        )
    except Exception as exc:  # noqa: BLE001 - a malformed incident is not fatal
        return store.record_delivery(
            {
                "capability": config.SLACK_POST.id,
                "target": incident_id,
                "state": config.ERROR,
                "ok": False,
                "error_code": "message_build_failed",
                "message": str(exc),
            }
        )

    result = client.execute(
        config.SLACK_POST,
        {"channel": channel(), "text": text, "mrkdwn": False},
        fixture="slack_chat_post_message.json",
    )

    data = result.data if isinstance(result.data, dict) else {}
    return store.record_delivery(
        {
            "capability": config.SLACK_POST.id,
            "target": incident_id,
            "state": result.state,
            "ok": result.ok,
            "error_code": result.error_code,
            "message": result.message,
            "channel": channel(),
            "message_ts": data.get("ts"),
            "latency_ms": result.latency_ms,
            "link": incident_url(incident_id),
            # The posted text is kept so the UI can show exactly what left the
            # building. It is assembled from allowlisted fields and checked.
            "text": text,
            "detection_unaffected": True,
        }
    )


def test_message():
    """One clearly labelled message, for the connection test endpoint."""
    return post_incident(
        {
            "incident_id": "connection-test",
            "severity": "high",
            "title": (
                "Minny connection test. No incident is being reported and no "
                "evidence is attached."
            ),
            "narrative": [],
            "evidence_lines": [],
            "labels": {"synthetic": False, "variant_id": None},
        },
        force=True,
    )
