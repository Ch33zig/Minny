"""Composio integrations: Slack outbound, Gmail inbound, GitHub outbound.

Nothing in here is on a critical path. The case file, the detector, the
incidents and the metrics are produced without asking a vendor anything, and
every function below fails soft into a result object rather than an
exception. The default mode is recorded fixtures with no credentials, which
is what the demo runs on.

    minny.integrations.config          capabilities, modes, what is connected
    minny.integrations.client          the one adapter, the one failure point
    minny.integrations.egress          what may never be published
    minny.integrations.mailbox         the bounded query and linking rules
    minny.integrations.gmail_evidence  the sync that writes the evidence store
    minny.integrations.slack           high severity alerting
    minny.integrations.github_pr       a pull request for an accepted rule
    minny.integrations.store           artifacts and the delivery log
"""

from minny.integrations import (  # noqa: F401
    client,
    config,
    egress,
    gmail_evidence,
    github_pr,
    mailbox,
    slack,
    store,
)

__all__ = [
    "client",
    "config",
    "egress",
    "gmail_evidence",
    "github_pr",
    "mailbox",
    "slack",
    "store",
]
