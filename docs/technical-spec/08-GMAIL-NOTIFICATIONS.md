# Gmail notifications through Composio

Scope revision: Gmail is required implementation scope and an optional, explicitly enabled channel for each user. P3 owns integration/policy/delivery; P4 owns Settings/history; P1 owns shared persistence/API registration. This draft does not authorize or perform any email sends.

## 1. Purpose and event selection

Send operational notifications from the user's connected Gmail identity to their explicitly selected recipients. GitHub remains the remediation record. Slack and Gmail consume the same persisted domain events; neither channel owns detection or approval state.

| Event | Default when Gmail enabled | Email content |
|---|---|---|
| `gap_confirmed` | On | Technique, synthetic variant, miss summary, Minny detail link; issue URL when already available |
| `proposal_ready` | On | Issue/PR links, validation summary, request for human GitHub review |
| `remediation_verified` | On | Actual merged commit, replay result, evidence link, verified timestamp |
| `verification_failed` | On | Complete miss versus invalid rule versus infrastructure error, next action, open issue link |
| `experiment_failed` | Off | Stage/error summary; no claim of attack evasion |
| `connection_attention` | Off | Reconnect link for another affected integration; do not attempt Gmail delivery through a revoked Gmail connection |

Do not email every telemetry event or mutation step. Deduplicate by persisted event ID, channel, policy revision, and recipient. A replay retry is not a new success event. No password-reset/invitation mail, inbound inbox reading, email-based merge approvals, or auto-replies in this scope.

## 2. Developer setup

1. Add `gmail` to the selected Composio toolkits and create/select its managed OAuth auth config. Store `COMPOSIO_AUTH_CONFIG_GMAIL`; pin `COMPOSIO_TOOLKIT_VERSION_GMAIL=20260915_00` only after confirming the catalog version is available and exporting its schemas.
2. Allowlist `GMAIL_SEND_EMAIL`. The official toolkit lists managed OAuth and this sending tool. Export its actual pinned input/output schema and verify recipient, subject, body, body-format, and returned message/thread identifiers. Do not infer argument spellings from another toolkit. [Composio Gmail catalog](https://docs.composio.dev/toolkits/gmail).
3. Target `https://www.googleapis.com/auth/gmail.send` for sending. This is a sensitive Google scope. Do not request `gmail.readonly`, `gmail.modify`, or full mailbox access solely to send notifications. Inspect managed auth's actual grant; use a suitably scoped auth config if defaults exceed requirements. [Google scope reference](https://developers.google.com/workspace/gmail/api/auth/scopes).
4. Identify the account from Composio's verified connected-account metadata. Do not add `GMAIL_GET_PROFILE` blindly: a profile operation can require permissions that send-only access does not grant. If reliable sender metadata is unavailable, display “Connected Google account” and require the user to confirm the intended identity through a test send; never display an unverified address as provider-confirmed.
5. If using your own Google OAuth app instead of managed auth: enable Gmail API in that Google Cloud project, configure the consent screen/audience/test users, and register the exact OAuth redirect URI supplied by Composio. That Google-to-Composio redirect is distinct from the Composio-to-Minny callback. Confirm verification/Workspace administrator requirements for the chosen deployment before promising public onboarding.
6. Run a labeled test send to a team-controlled recipient through the real app flow. Preserve sanitized execution/message IDs and the received test result separately.

No extra Gmail API key, SMTP password, app password, or service-account delegation is needed in the chosen delegated OAuth design. Provider approval failure is a setup error, not a reason to ask users for mailbox passwords.

## 3. User setup

1. Settings → Integrations → Gmail → Connect uses the existing secure hosted Connect Link flow, with toolkit `gmail`, one-use attempt nonce, and server-derived user/workspace identity.
2. User authorizes their Google account. Backend rechecks account ownership, toolkit/auth config, and ACTIVE status; callback query parameters alone never establish a connection.
3. Settings shows the sender identity when verified, recipient list, and event checkboxes. It must state: “These notifications will be sent from your connected Gmail account.” Minny does not spoof a central company sender.
4. User adds 1–5 recipients, explicitly enables email, and saves consent. No recipient is inferred from a dataset, model output, GitHub issue text, workspace member list, or unverified app-login email.
5. Validate single-mailbox address syntax with a maintained parser; reject CR/LF, display-name/header injection, comma-separated hidden recipients, and duplicates. Preserve the local part; normalize the domain. This checks syntax, not ownership or deliverability. Show the exact recipients before enable/test.
6. “Send test email” queues a labeled message and exposes its status. Send one message per recipient; no CC/BCC, preventing recipients from being disclosed to one another.
7. Gmail must work without Slack enabled. Users can choose Slack, Gmail, or both. GitHub workflow remains available if either notification provider is unavailable.

Use the same reconnect/disconnect safeguards as other toolkits. Disconnect Gmail pauses Gmail deliveries only; it does not disable the GitHub trigger or Slack notifications. Gmail needs no inbound trigger subscription for this feature.

## 4. Policy and message contracts

```json
{
  "channel": "gmail",
  "connection_id": "owned-application-connection-id",
  "enabled": true,
  "recipients": ["security@example.com"],
  "event_types": ["gap_confirmed", "proposal_ready", "remediation_verified", "verification_failed"],
  "revision": 1
}
```

Illustrative address/ID only. Backend verifies connection ownership and membership. Store the consent timestamp, actor, policy revision, and exact recipient snapshot with each delivery. Recheck current consent and account state immediately before sending. Disabling a policy cancels unsent deliveries; removing a recipient cancels that recipient's unsent deliveries. Adding a recipient does not retroactively send old events. Other policy changes invalidate pending old-revision deliveries; do not silently reroute them.

Message subject: `[Minny][Detection gap] T1059.001 · <short-variant-id>`; choose analogous labels for proposal/verified/failed. Body is deterministic plain text assembled from validated event fields, capped at 20 KiB, containing workspace name, summary, technique/variant IDs, outcome, relevant GitHub/Minny links, timestamp, and a notification identifier. No attachments, raw CSE logs, OAuth URLs, credentials, executable content, or model-selected recipients. Do not set arbitrary From aliases; use the connected account's supported sender.

Initial implementation sends each lifecycle event as a standalone message. Do not assume repeating the subject creates a reliable Gmail thread. Threading is a later feature requiring correct thread ID and message headers under the Gmail API. [Sending messages](https://developers.google.com/workspace/gmail/api/guides/sending).

## 5. Durable delivery and recovery

Use the existing outbox and `notification_deliveries` table. Logical key is `gmail:<domain_event_id>:<policy_revision>:<recipient_digest>`. Persist intent before invoking Composio; store provider message/thread IDs when returned. Per-recipient status: `queued`, `sending`, `sent`, `failed`, `uncertain`, `cancelled`, `needs_connection`.

“Sent” means Gmail accepted the API operation; it does not prove recipient delivery, inbox placement, opening, or reading. Do not display “Delivered” without a separate verified delivery mechanism. No inbound bounce tracking is implemented.

Definite rate-limit rejection: respect Retry-After and retry at most three attempts. Auth/permission rejection: pause, reconnect or correct grant. Timeout/network loss/ambiguous server failure after submission: mark `uncertain`; Gmail sending has no assumed exactly-once guarantee. With send-only grants, do not automatically broaden access to search Sent Mail, and do not blindly resend. Show “May have been sent—check Sent Mail before retrying”; explicit owner retry records duplicate-risk acknowledgement and a new attempt identifier. Ordinary repeated clicks retain the same idempotency key.

Application limits: at most 20 Gmail messages per owner/workspace/hour, including tests; additional messages stay queued and visibly delayed. Respect provider quotas independently; this local cap is not a statement about Gmail limits. Recheck eligibility before a delayed send. Stop retries on disable/disconnect or membership loss.

Detection/remediation status is independent from email status. A verified rule stays verified if Gmail fails; the UI shows the failed channel and a recovery action. Preserve successful Slack/GitHub actions when Gmail fails.

## 6. Files and tests

P3: `backend/workflows/gmail.py`, `notifications.py`, policy API router, vendor Gmail schemas, Gmail tests. P4: Gmail integration card, recipient/event settings, test-send action, delivery history, uncertain-send handling. P1: shared migrations/route registration. Scrub recipient addresses and email bodies from Sentry, logs, and Replay; keep only counts, event IDs, delivery IDs, and sanitized error codes in observability.

| Test | Expected result |
|---|---|
| G01 Two users connect Gmail | No cross-user account access or sends |
| G02 Declined/revoked/expired OAuth | Recoverable state, no fallback sender |
| G03 Invalid/header-injected recipient | Validation rejection before provider call |
| G04 Enabled event → actual test mailbox | Correct sender, recipient, content, links; provider ID retained |
| G05 Duplicate event/request | One intent per recipient, no duplicate automatic send |
| G06 Response lost after send | `uncertain`, no blind retry |
| G07 Gmail fails, Slack succeeds | Separate channel results; remediation unchanged |
| G08 Disable/remove recipient while queued | No pending delivery to disabled/removed destination |
| G09 Revoke connection during queue wait | `needs_connection`, no alternate identity |
| G10 Accepted Gmail result | UI says sent; never claims delivered/read |

Close-out requires Gmail schema export, actual granted-scope inspection, real test send, and negative/recovery tests. This document specifies those gates; none has yet been run against team accounts.
