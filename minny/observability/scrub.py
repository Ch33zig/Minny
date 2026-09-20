"""What never leaves this process.

Every identifier in this dataset is a person. The logs are one account
watching another account's session, so a span description carrying a
username, an error message quoting a log line, or a breadcrumb holding a
mailbox subject would move the whole case out of the machine it belongs on
and into an error tracker. This module is the last thing every payload
passes through, in both modes, and it is deliberately the dullest code here.

Six rules, applied in this order for a reason:

1. **Whole log lines** go first. A Combined Log Format line contains an
   address and an account, so replacing it as a unit is both cheaper and
   safer than letting the later rules pick it apart and leave the request
   path, the byte count and the timestamp behind.
2. **Email addresses**, before the username rule, because the local part of
   an address is often the account name and a half-scrubbed address is worse
   than either outcome.
3. **IPv6 then IPv4.** IPv6 first because an IPv4-mapped address ends in a
   dotted quad that the v4 rule would eat, leaving a torso behind.
4. **Usernames**, from a registry the application fills in plus a pattern
   matching this dataset's `name_initial` shape. The pattern requires a
   single-letter suffix, which is what keeps it off identifiers like
   `rule_id` and `variant_id` that are all over these spans.
5. **Sensitive keys**, by name, whatever the value looks like. Mailbox
   bodies and request payloads are replaced entirely rather than pattern
   matched, because there is no pattern for prose.
6. **Length**, last. A value that survives the first five rules and is still
   longer than a sentence is a payload somebody forgot about.

The walk is recursive over the whole event, not a list of known Sentry
fields. A field the SDK adds in a later version would otherwise arrive
unscrubbed, and the failure mode of scrubbing too much is a less useful
error report while the failure mode of scrubbing too little is a person's
name in somebody else's database.
"""

from __future__ import annotations

import re
import threading

USER_TOKEN = "[user]"
IP_TOKEN = "[ip]"
EMAIL_TOKEN = "[email]"
LOG_TOKEN = "[log line]"
REDACTED = "[redacted]"
TRUNCATED = "[truncated]"

MAX_VALUE_CHARS = 512

# Keys whose value is content rather than a label. Matched case-insensitively
# against the exact key, not a substring, so `body_bytes` is not mistaken for
# a message body.
SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "api_key",
        "attachment",
        "body",
        "body_html",
        "body_text",
        "cookie",
        "cookies",
        "credentials",
        "dsn",
        "headers",
        "html",
        "mailbox",
        "message_body",
        "password",
        "payload",
        "raw",
        "raw_line",
        "request_body",
        "secret",
        "snippet",
        "subject",
        "token",
    }
)

# Whole sections of a Sentry event that carry identity by design.
DROPPED_SECTIONS = ("user",)

_LOG_LINE = re.compile(
    r"(?:\d{1,3}\.){3}\d{1,3}\s+-\s+\S+\s+\[[^\]]*\]\s+\"[^\"]*\"\s+\d{3}\s+\d+"
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
# The compressed branch requires a `::`, which is what keeps a clock time
# such as 11:26:59 from being read as an address.
_IPV6 = re.compile(
    r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"
    r"|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}\b"
)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# firstname_initial, with exactly one letter after the underscore.
_USERNAME_SHAPE = re.compile(r"\b[A-Za-z][A-Za-z0-9]{2,19}_[A-Za-z]\b")

RULES = (
    ("log_line", "a whole Combined Log Format line, replaced as a unit"),
    ("email", "an email address, local part included"),
    ("ip", "an IPv4 or IPv6 address"),
    ("username", "a registered account name or the dataset's name_initial shape"),
    ("sensitive_key", "the value of a key that holds content rather than a label"),
    ("length", "any value still longer than 512 characters"),
)


class Scrubber:
    """Stateful only in its counters, which is what makes it testable."""

    def __init__(self):
        self._lock = threading.Lock()
        self.counts = {name: 0 for name, _ in RULES}
        self.identifiers: set = set()
        self._identifier_pattern: re.Pattern | None = None

    # ------------------------------------------------------------ registry

    def register(self, names) -> int:
        """Teach the scrubber the account names this workspace actually has.

        The shape pattern is a backstop, not the mechanism. A deployment
        whose accounts are called `svc-ingest-07` gets nothing from a pattern
        built for `sarah_j`, so the names are registered from the baseline
        model at startup and the pattern only catches what the registry
        missed.
        """
        added = 0
        with self._lock:
            for name in names or ():
                text = str(name).strip()
                if len(text) < 3 or text in self.identifiers:
                    continue
                self.identifiers.add(text)
                added += 1
            if added:
                self._identifier_pattern = re.compile(
                    r"\b(?:%s)\b"
                    % "|".join(
                        re.escape(name)
                        for name in sorted(self.identifiers, key=len, reverse=True)
                    )
                )
        return added

    def reset(self) -> None:
        with self._lock:
            for name in self.counts:
                self.counts[name] = 0

    def _hit(self, rule: str, times: int = 1) -> None:
        if times:
            self.counts[rule] = self.counts.get(rule, 0) + times

    # -------------------------------------------------------------- text

    def scrub_text(self, text: str) -> str:
        if not text:
            return text
        value = str(text)

        value, hits = _LOG_LINE.subn(LOG_TOKEN, value)
        self._hit("log_line", hits)

        value, hits = _EMAIL.subn(EMAIL_TOKEN, value)
        self._hit("email", hits)

        value, hits = _IPV6.subn(IP_TOKEN, value)
        self._hit("ip", hits)
        value, hits = _IPV4.subn(IP_TOKEN, value)
        self._hit("ip", hits)

        pattern = self._identifier_pattern
        if pattern is not None:
            value, hits = pattern.subn(USER_TOKEN, value)
            self._hit("username", hits)
        value, hits = _USERNAME_SHAPE.subn(USER_TOKEN, value)
        self._hit("username", hits)

        if len(value) > MAX_VALUE_CHARS:
            self._hit("length")
            value = f"{value[:MAX_VALUE_CHARS]} {TRUNCATED}"
        return value

    # ------------------------------------------------------------- values

    def scrub(self, value, key: str | None = None, depth: int = 0):
        """Walk anything and hand back the same shape, cleaned."""
        if depth > 12:
            return REDACTED
        if key is not None and str(key).lower() in SENSITIVE_KEYS:
            self._hit("sensitive_key")
            return REDACTED
        if isinstance(value, str):
            return self.scrub_text(value)
        if isinstance(value, dict):
            return {
                name: self.scrub(item, key=name, depth=depth + 1)
                for name, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            cleaned = [self.scrub(item, key=key, depth=depth + 1) for item in value]
            return type(value)(cleaned) if isinstance(value, tuple) else cleaned
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        return self.scrub_text(str(value))

    # ------------------------------------------------- the sentry hooks

    def before_send(self, event, hint=None):
        """`before_send`, and it never returns an unscrubbed event.

        A failure inside the scrubber drops the event rather than letting it
        through. Losing an error report is an inconvenience; sending an
        account name to an error tracker because the redactor raised is not.
        """
        try:
            return self._scrub_event(event)
        except Exception:  # noqa: BLE001 - drop, never pass through
            return None

    # Transactions and breadcrumbs are separate products with separate
    # payloads; scrubbing errors does not sanitise either of them.
    before_send_transaction = before_send

    def before_breadcrumb(self, crumb, hint=None):
        try:
            return self.scrub(crumb)
        except Exception:  # noqa: BLE001
            return None

    def _scrub_event(self, event):
        if not isinstance(event, dict):
            return self.scrub(event)
        cleaned = {}
        for key, value in event.items():
            if key in DROPPED_SECTIONS:
                self._hit("sensitive_key")
                continue
            cleaned[key] = self.scrub(value, key=key)
        return cleaned

    # ------------------------------------------------------------ report

    def describe(self) -> dict:
        return {
            "rules": [{"rule": name, "what": what} for name, what in RULES],
            "order": [name for name, _ in RULES],
            "redactions": dict(self.counts),
            "registered_identifiers": len(self.identifiers),
            "max_value_chars": MAX_VALUE_CHARS,
            "dropped_sections": list(DROPPED_SECTIONS),
            "sensitive_keys": sorted(SENSITIVE_KEYS),
            "send_default_pii": False,
        }


SCRUBBER = Scrubber()


def register_identifiers(names) -> int:
    return SCRUBBER.register(names)


def scrub(value, key: str | None = None):
    return SCRUBBER.scrub(value, key=key)


def scrub_text(text: str) -> str:
    return SCRUBBER.scrub_text(text)


def before_send(event, hint=None):
    return SCRUBBER.before_send(event, hint)


def before_send_transaction(event, hint=None):
    return SCRUBBER.before_send_transaction(event, hint)


def before_breadcrumb(crumb, hint=None):
    return SCRUBBER.before_breadcrumb(crumb, hint)


def describe() -> dict:
    return SCRUBBER.describe()
