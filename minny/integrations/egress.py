"""The gate every outbound payload passes through before it leaves.

Two source records exist in this system and neither one may be published to
a third party:

* **Raw log lines.** They are the primary evidence and they belong behind
  `GET /api/events`, which is Minny's own access-controlled surface.
* **Mailbox content.** Subjects, snippets, addresses, message ids. Contracts
  section 11 is explicit: nothing from the mailbox leaves the app, not into a
  GitHub issue, not into a PR body, not into Slack. This matches the rule in
  04-COMPOSIO.md section 7 about never publishing raw source records.

What goes out instead is a Minny link. A reader who is entitled to the
evidence follows it and sees the evidence; a reader who is not, does not.

Slack and GitHub payloads are assembled field by field from an allowlist, so
in normal operation nothing here ever fires. It fires when somebody later
adds a convenient `"\\n".join(evidence)` to a message body, which is exactly
the change that would otherwise ship unnoticed.
"""

from __future__ import annotations

import re

# An Apache combined line, which is what every record in logs.txt looks like.
# Matching loosely on purpose: the point is to catch a log line that got
# pasted into a message, not to parse it.
RAW_LOG_LINE = re.compile(
    r"\d{1,3}(?:\.\d{1,3}){3}\s+\S+\s+\S+\s+\[\d{2}/[A-Za-z]{3}/\d{4}"
)

# A bare Gmail message id as it appears in an evidence id or a permalink.
GMAIL_ID = re.compile(r"\bgmail:[0-9a-f]{6,}\b|mail\.google\.com/mail/")

# Text short enough to be a coincidence rather than a quotation. A three word
# fragment can legitimately appear in both a subject line and an incident
# title, so only substantial runs count as mailbox content.
MIN_QUOTE_CHARS = 24


class EgressRefused(Exception):
    """A payload carried something that may not be published.

    Raised inside the integration layer and caught there. It never reaches a
    request handler and it never changes anything about the detection.
    """

    def __init__(self, reason: str, sample: str = ""):
        self.reason = reason
        self.sample = sample
        super().__init__(reason)


def mailbox_strings(store: dict | None) -> list[str]:
    """Every string in the email store that must never be republished."""
    if not store:
        return []
    out: list[str] = []
    for message in store.get("messages", []):
        for key in ("subject", "snippet", "from", "permalink", "evidence_id", "message_id"):
            value = message.get(key)
            if isinstance(value, str) and value.strip():
                out.append(value.strip())
        for address in message.get("to", []) or []:
            if isinstance(address, str) and address.strip():
                out.append(address.strip())
    return out


def check(text: str, *, store: dict | None = None) -> None:
    """Refuse a payload that quotes a source record. Returns None or raises."""
    if not text:
        return

    match = RAW_LOG_LINE.search(text)
    if match:
        raise EgressRefused("raw_log_line", match.group(0))

    match = GMAIL_ID.search(text)
    if match:
        raise EgressRefused("mailbox_identifier", match.group(0))

    haystack = text.casefold()
    for candidate in mailbox_strings(store):
        if len(candidate) < MIN_QUOTE_CHARS:
            continue
        if candidate.casefold() in haystack:
            raise EgressRefused("mailbox_content", candidate[:60])


def safe(text: str, *, store: dict | None = None) -> bool:
    try:
        check(text, store=store)
    except EgressRefused:
        return False
    return True
