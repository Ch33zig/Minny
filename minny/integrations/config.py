"""Which vendor capabilities exist, and what state each one is in.

Nothing in this module touches the network. It reads the environment and
reports one state per capability, never a single "integrations: on" boolean.
That distinction is load-bearing in two places:

* Gmail read and Gmail send are two separate OAuth grants. A person who
  authorised notifications has not authorised evidence collection, and the
  UI has to be able to say so.
* A capability can be connected, running on recorded fixtures, or broken,
  and those are three different things to a judge looking at the screen.

Mode resolution, in order:

    MINNY_INTEGRATIONS_MODE=mock   force fixtures even if keys are present
    MINNY_INTEGRATIONS_MODE=live   attempt the vendor, report the failure
    unset, or "auto"               live when the keys for that capability
                                   are present, fixtures otherwise

Default is auto, and with no credentials on the machine that means every
capability runs on recorded fixtures. That is the path the demo runs on.

Setup, tool slugs and scopes: docs/technical-spec/04-COMPOSIO.md sections 3,
6 and 11, and docs/technical-spec/08-GMAIL-NOTIFICATIONS.md section 2.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Capability states. `mock` is a first class state, not a degraded one: it is
# what runs on stage, and the UI labels it rather than hiding it.
CONNECTED = "connected"
MOCK = "mock"
ERROR = "error"

AUTO = "auto"
LIVE = "live"

API_KEY_ENV = "COMPOSIO_API_KEY"
MODE_ENV = "MINNY_INTEGRATIONS_MODE"

# Where a Minny link points. Slack and GitHub carry one of these instead of
# the evidence itself, so the address has to be configurable per deployment.
BASE_URL_ENV = "MINNY_PUBLIC_BASE_URL"
DEFAULT_BASE_URL = "http://localhost:8080"

# Toolkit versions are pinned rather than tracking `latest`, because this code
# parses the responses. 04-COMPOSIO.md section 3 step 5.
TOOLKIT_VERSIONS = {
    "github": os.environ.get("COMPOSIO_TOOLKIT_VERSION_GITHUB", "20260916_00"),
    "slack": os.environ.get("COMPOSIO_TOOLKIT_VERSION_SLACK", "20260915_00"),
    "gmail": os.environ.get("COMPOSIO_TOOLKIT_VERSION_GMAIL", "20260915_00"),
}


@dataclass(frozen=True)
class Capability:
    """One grant, one tool slug, one direction.

    `tool_slug` is the only Composio tool this capability is ever allowed to
    call. The adapter refuses anything else, which is what keeps an
    integration layer from turning into unrestricted vendor access.
    """

    id: str
    label: str
    short: str
    toolkit: str
    tool_slug: str
    direction: str
    scope: str | None
    auth_config_env: str
    summary: str


SLACK_POST = Capability(
    id="slack.post",
    label="Slack alerting",
    short="SLACK",
    toolkit="slack",
    tool_slug="SLACK_CHAT_POST_MESSAGE",
    direction="outbound",
    scope="chat:write",
    auth_config_env="COMPOSIO_AUTH_CONFIG_SLACK",
    summary=(
        "Posts the plain English explanation and a Minny link when a high "
        "severity incident opens. Never a log line, never mailbox content."
    ),
)

GMAIL_READ = Capability(
    id="gmail.read",
    label="Gmail evidence",
    short="MAIL IN",
    toolkit="gmail",
    tool_slug="GMAIL_FETCH_EMAILS",
    direction="inbound",
    scope="https://www.googleapis.com/auth/gmail.readonly",
    auth_config_env="COMPOSIO_AUTH_CONFIG_GMAIL_READ",
    summary=(
        "Runs three fixed, app coded queries over a bounded window and stores "
        "headers, category, matched entities and snippet. Never bodies."
    ),
)

GMAIL_SEND = Capability(
    id="gmail.send",
    label="Gmail notifications",
    short="MAIL OUT",
    toolkit="gmail",
    tool_slug="GMAIL_SEND_EMAIL",
    direction="outbound",
    scope="https://www.googleapis.com/auth/gmail.send",
    auth_config_env="COMPOSIO_AUTH_CONFIG_GMAIL",
    summary=(
        "A separate grant from the evidence scope. Authorising one does not "
        "authorise the other, so the two are reported independently."
    ),
)

GITHUB_PR = Capability(
    id="github.pr",
    label="GitHub review",
    short="GITHUB",
    toolkit="github",
    tool_slug="GITHUB_CREATE_A_PULL_REQUEST",
    direction="outbound",
    scope="repo",
    auth_config_env="COMPOSIO_AUTH_CONFIG_GITHUB",
    summary=(
        "Opens a pull request carrying the evaded variant, the gate results "
        "and the false positive numbers. Merging stays a human action."
    ),
)

CAPABILITIES: tuple[Capability, ...] = (SLACK_POST, GMAIL_READ, GMAIL_SEND, GITHUB_PR)
BY_ID = {cap.id: cap for cap in CAPABILITIES}

# Every slug this layer may ever execute. An argument-shaped mistake reaching
# a tool nobody reviewed is the failure mode this list exists to prevent.
ALLOWED_SLUGS = frozenset(cap.tool_slug for cap in CAPABILITIES)


def base_url() -> str:
    """The origin a Slack message or a PR body links back to."""
    return (os.environ.get(BASE_URL_ENV) or DEFAULT_BASE_URL).rstrip("/")


def requested_mode() -> str:
    value = (os.environ.get(MODE_ENV) or AUTO).strip().lower()
    return value if value in {AUTO, LIVE, MOCK} else AUTO


def api_key() -> str | None:
    return os.environ.get(API_KEY_ENV) or None


def auth_config(cap: Capability) -> str | None:
    """The auth config id for this capability's toolkit.

    Gmail read falls back to the shared Gmail auth config so a deployment
    that granted one Gmail connection does not have to name it twice. The two
    capabilities stay reported separately either way.
    """
    direct = os.environ.get(cap.auth_config_env)
    if direct:
        return direct
    if cap.toolkit == "gmail":
        return os.environ.get("COMPOSIO_AUTH_CONFIG_GMAIL") or None
    return None


def connected_account(cap: Capability) -> str | None:
    """The stored connected account id, per toolkit.

    Composio holds the tokens. Minny keeps only this identifier, per
    04-COMPOSIO.md section 2.
    """
    return os.environ.get(f"COMPOSIO_ACCOUNT_{cap.toolkit.upper()}") or None


def composio_user_id() -> str:
    """A stable server-side user id, never an email and never `default`."""
    return os.environ.get("COMPOSIO_USER_ID") or "minny-demo-owner"


def credentials_present(cap: Capability) -> bool:
    return bool(api_key()) and bool(auth_config(cap))


def should_attempt_live(cap: Capability) -> bool:
    """Whether a real call is even worth trying for this capability."""
    mode = requested_mode()
    if mode == MOCK:
        return False
    if mode == LIVE:
        return True
    return credentials_present(cap)


def missing_for(cap: Capability) -> list[str]:
    """Which environment variables stand between here and a live call."""
    missing = []
    if not api_key():
        missing.append(API_KEY_ENV)
    if not auth_config(cap):
        missing.append(cap.auth_config_env)
    return missing


def describe(cap: Capability) -> dict:
    """The per-capability record `GET /api/integrations/status` serves."""
    live = should_attempt_live(cap)
    return {
        "id": cap.id,
        "label": cap.label,
        "short": cap.short,
        "direction": cap.direction,
        "toolkit": cap.toolkit,
        "tool_slug": cap.tool_slug,
        "scope": cap.scope,
        "summary": cap.summary,
        "state": CONNECTED if live else MOCK,
        "credentials_present": credentials_present(cap),
        "missing_env": missing_for(cap),
        "toolkit_version": TOOLKIT_VERSIONS.get(cap.toolkit),
    }
