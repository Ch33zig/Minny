# Composio: complete connection and remediation specification

Owner: P3. P1 supplies identity/database/API registration. P4 supplies Settings UI. This integration is application functionality built into Minny; installing a Composio plugin into a developer's editor does not implement it.

## 1. Product purpose and integration selection

Use **GitHub, Slack, and Gmail deeply**. GitHub is the record of a discovered gap, the reviewed detection change, and the source of the merged rule. Slack is the team's operational notification thread and link back to review/evidence. Composio handles delegated connections and all application GitHub/Slack/Gmail operations in this lifecycle.

| Integration | Required functionality | Real user value |
|---|---|---|
| GitHub read | List/select accessible repository, read branch/rules, inspect PR and merged content | Work against the user's actual detection repository |
| GitHub write | Issue, branch, rule-file commit, PR, comments, issue closure | A reviewable detection-as-code change with provenance |
| GitHub inbound | PR event plus authoritative merge verification | User's merge automatically starts verification |
| Slack write | Gap thread, PR-ready reply, replay outcome, reconnect/failure status | Security team can follow the gap without watching Minny |
| Slack read | Identify workspace/channels; optionally reconcile a known thread | Correct destination and recoverable notifications |

Gmail is an additional user-selectable notification channel, specified in [the Gmail addendum](08-GMAIL-NOTIFICATIONS.md). Its events come from the same remediation state as Slack. Do not add Jira or Notion as duplicate work/evidence stores. Optional later functionality is GitHub review-comment feedback to Blue, with the same validation-before-publish boundary.

## 2. Distinguish the five identities

1. **Minny user:** signed-in person from the app database.
2. **Minny workspace:** data/authorization boundary.
3. **Composio project:** developer-side environment and API key.
4. **Auth config:** developer-controlled OAuth blueprint for a toolkit.
5. **Connected account:** one authorized user's GitHub, Slack, or Gmail identity, stored by Composio.

Use stable server-generated user IDs, never email or a shared `default` user. Tokens remain at Composio; Minny retains only connection identifiers and sanitized metadata. [Authentication model](https://docs.composio.dev/docs/authentication).

Development and deployed demo must use separate Composio projects if developers need different webhook destinations. One teammate changing the shared webhook URL must not steal everyone else's events. Only P3 controls the demo project's webhook configuration.

## 3. Developer provisioning, in order

1. Create a Composio account/project `minny-dev`, then a separate `minny-demo` when deploying. Record project identifiers and environment, not keys, in `docs/service-manifest.json`.
2. Generate a project API key and store it only in backend/worker secret configuration as `COMPOSIO_API_KEY`.
3. In the dashboard, create/select managed OAuth auth configs for the `github`, `slack`, and `gmail` toolkits. Record `COMPOSIO_AUTH_CONFIG_GITHUB` `COMPOSIO_AUTH_CONFIG_SLACK`, and `COMPOSIO_AUTH_CONFIG_GMAIL`. Do not ask end users to create Composio accounts or supply your project key.
4. Inspect each selected toolkit's supported tools, OAuth scheme, grant/scopes, versions, and trigger schemas. Export only schema/metadata, never connected-account credentials.
5. Pin toolkit versions. The catalog inspected for this draft showed GitHub `20260916_00` and Slack `20260915_00`. Confirm these are available in the project, save them in configuration, and run schema smoke tests. Do not use `latest` for code that parses outputs. [Versioning](https://docs.composio.dev/docs/tools-direct/toolkit-versioning).
6. Prepare a dedicated detection-rules repository with an initial commit, a real default branch, Issues enabled, and `detection-rules/` containing baseline JSON. It may be a selected folder of Minny, but a separate demo rules repository avoids application-code conflicts. The user chooses/creates it; the app does not silently create repositories.
7. Prepare a Slack test workspace/channel such as `#minny-soc`. Confirm the person can authorize the integration. Add the connected app/bot to the channel when required by the selected auth mode.
8. Run the actual browser connection flow as a demo owner, then verify read capabilities and selected destinations.
9. Register the public callback base and signed event endpoint. Set up the repository trigger using the chosen GitHub connected account.
10. Complete the issue → PR → human merge → replay smoke test. OAuth success by itself does not pass integration setup.

### Permissions: capabilities first, verified grants second

GitHub must allow reading the selected repository, writing Issues and Contents/branches/PRs, and installing/receiving the repository trigger. For a custom GitHub OAuth app, `repo` is the broad private-repository scope; public-only setups can use `public_repo`, and repository-hook administration may require `admin:repo_hook` depending on hook setup. These OAuth scopes are broader than a single repo. Minny's repository allowlist is an application restriction, not a promise that OAuth granted access only to that repository. Organizations can require separate OAuth/SSO approval. [GitHub scope semantics](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps).

For Slack, required capabilities are connection identity, channel discovery, posting messages/replies, and obtaining message permalinks. Public channel discovery commonly uses `channels:read`; private discovery uses `groups:read`. Posting scope and identity depend on user-token versus bot-token auth; inspect the selected toolkit's actual schema/grants rather than assuming a bot. `chat:write` alone does not grant membership in arbitrary private channels. Do not request admin/workspace-wide history access to post a notification. [Slack chat scope](https://docs.slack.dev/reference/scopes/chat.write/).

Use managed auth defaults initially and record actual consent grants. If insufficient or excessive for the deployment, create a scoped managed/custom auth config, reconnect, and rerun capability probes. Composio supports scope configuration on auth configs, but a config change does not prove an existing token has new permissions. [Scope configuration](https://docs.composio.dev/docs/authentication/controlling-scopes).

## 4. Pinning and schema capture

Use a deterministic adapter around Composio, not unrestricted agent access to every tool. Direct execution fits this fixed workflow. Only expose application intents such as `publish_validated_proposal` to the supervisor; repository/channel/connection values come from stored policy.

```python
from composio import Composio

composio = Composio(
    api_key=settings.composio_api_key,
    toolkit_versions={
        "github": settings.composio_github_version,
        "slack": settings.composio_slack_version,
        "gmail": settings.composio_gmail_version,
    },
)

result = composio.tools.execute(
    "GITHUB_CREATE_AN_ISSUE",
    user_id=principal.composio_user_id,
    connected_account_id=destination.github_connected_account_id,
    arguments={
        "owner": destination.owner,
        "repo": destination.repo,
        "title": issue_title,
        "body": issue_body,
    },
)
```

Inspect both the Composio execution envelope and the underlying provider result. HTTP success does not necessarily mean the provider action succeeded. Parse into small application result types (`IssueRef`, `PullRequestRef`, `MessageRef`) and preserve a sanitized provider response for debugging. [Direct execution](https://docs.composio.dev/docs/tools-direct/executing-tools).

Required setup script `scripts/composio/export_contracts.py` must use the pinned toolkit metadata/tool schema APIs to export selected input/output schemas and trigger config/payload schema into `contracts/vendor/composio/`. Current documented REST tool lookup is `GET https://backend.composio.dev/api/v3.1/tools/{tool_slug}?version=<pinned-version>` with server `x-api-key`. Verify the exact response through the installed SDK/API and store the schema hash. Refuse startup of workflow capability if a required slug or required input field is absent; do not silently swap tools.

The table below supplies the intended provider semantics. Catalog slugs were verified, but account-specific input/output schemas have not been executed because no project exists. Exporting and testing them is a required deliverable, not permission to guess argument shapes. [Schema discovery](https://docs.composio.dev/docs/tools-direct/fetching-tools).

## 5. User connection flow

Settings → Integrations contains GitHub, Slack, and Gmail cards with states `not_connected`, `connecting`, `active`, `insufficient_permissions`, `expired`, `disconnected`, `error`.

### Connect

1. Signed-in owner clicks Connect GitHub/Slack/Gmail. Browser sends CSRF-protected POST to the workspace integration endpoint.
2. Server verifies owner membership; computes Composio user ID; creates a 32-byte random attempt nonce and stores its hash, actor, workspace, toolkit, auth config, and a 10-minute expiry.
3. Server builds a fixed-origin callback URL: `/api/v1/integrations/composio/callback?attempt=<nonce>`. Never accept an arbitrary callback/redirect URL from the browser.
4. Server requests a hosted link:

```python
request = composio.connected_accounts.link(
    user_id=composio_user_id,
    auth_config_id=selected_auth_config_id,
    callback_url=callback_url,
)
redirect_url = request.redirect_url
```

5. Return the URL to the browser, which navigates the same tab. Do not hold an HTTP request open polling for authorization. Hosted `link()` is the chosen path; old managed-OAuth `initiate()` examples are not the implementation target. [Connect Link and callback fields](https://docs.composio.dev/docs/tools-direct/authenticating-tools).
6. User selects their provider identity and authorizes access at GitHub/Slack/Google. Decline/cancel returns the card to a recoverable state.
7. Callback receives `status` and `connected_account_id`. Treat both as untrusted hints. Validate nonce, expiry, unused status, and current user's session (or require re-login before completing attachment).
8. Fetch the connected account server-side. Confirm it belongs to the expected Composio user, auth config/toolkit, and is ACTIVE. If the object omits ownership fields, confirm membership through the user-scoped account-list response. Never attach an account solely because its ID was supplied in a callback.
9. Consume the attempt atomically, store the connection, and run identity/read capability probes. Redirect with 303 to Settings. Strip callback parameters; set no-store and a restrictive referrer policy on callback responses.
10. A callback replay, altered account ID, different user, or expired nonce must fail without attaching credentials. Log only attempt ID/outcome, not raw nonce or OAuth URL.

Use `allow_multiple=True` only when explicitly implementing additional account selection. For v1, a second active account is a conflict with a reconnect/change-account flow. Connect attempt expiry is Minny's policy and is not a claim about Composio's hosted-link expiry.

### Choose destinations

After GitHub becomes active, list accessible repositories with pagination. Show name, visibility, default branch, and capability status. Save immutable provider `repo_id` plus owner/name; names may change. Validate base branch exists and rule prefix is a normalized relative path under `detection-rules/` (reject `..`, absolute paths, symlink traversal, encoded separators). Read existing baseline rule files. Missing bootstrap content shows a setup action, not a ready state.

After Slack becomes active, show authorized workspace identity and channel choices. Save `team_id` and `channel_id`, not just channel name. Reject archived/unusable channels. Private channels require actual membership. Do not automatically join or create channels.

Save destinations only after provider reads verify them. A separate “Send test notification” action creates a clearly labeled message and stores its returned `ts`/permalink. A “Test GitHub workflow” action creates a clearly labeled issue/branch/PR in the selected test repository; this is an explicit onboarding action, not a hidden write probe.

Finally show and save the automation consent described in document 01. Ready checklist: identity active, repo readable/writable, rule path initialized, channel test passed if notifications enabled, trigger active/tested, webhook reachable, consent current.

### Reconnect and disconnect

- Poll connection status during setup and before external writes. Expiration events also update state. A stale UI badge cannot authorize a call.
- Reconnect uses a new hosted link and re-verifies ownership/capabilities. Bind the replacement account only after verification; recreate its trigger and preserve old artifact references.
- Disconnect first disables the affected toolkit policy and pending writes, then disables/deletes associated triggers and the owned connected account. Disconnecting a notification-only account pauses only that channel; GitHub publication/merge verification and other notification channels continue. Record partial cleanup failure for retry. Do not delete GitHub issues/PRs or Slack history.
- Queued external actions pause as `needs_connection`. Never fall back to another active account automatically.
- Composio supports disable/delete operations; disconnecting in Minny is distinct from revoking the provider-side OAuth app grant, which the user can also do in provider settings. [Connection lifecycle](https://docs.composio.dev/docs/auth-configuration/connected-accounts).

## 6. Exact tool inventory and chaining

GitHub catalog: [GitHub toolkit](https://docs.composio.dev/toolkits/github). Slack catalog: [Slack toolkit](https://docs.composio.dev/toolkits/slack). Only allow the selected slugs in the adapter, not the full toolkit.

| Operation | Composio tool slug | Required semantic arguments / outputs |
|---|---|---|
| Repository picker | `GITHUB_LIST_REPOSITORIES_FOR_THE_AUTHENTICATED_USER` | Pagination → ID/name/permissions/default branch |
| Verify repository | `GITHUB_GET_A_REPOSITORY` | owner, repo → repo ID and settings |
| Read base reference | `GITHUB_GET_A_REFERENCE` | owner, repo, ref=`heads/<base>` → commit SHA |
| Read rule at ref | `GITHUB_GET_REPOSITORY_CONTENT` | owner, repo, path, ref=commit SHA → bytes/content encoding/blob SHA |
| Create gap | `GITHUB_CREATE_AN_ISSUE` | owner/repo/title/body → issue number, URL |
| Add status/evidence comment | `GITHUB_CREATE_AN_ISSUE_COMMENT` | owner/repo/issue_number/body → comment ID |
| Create branch | `GITHUB_CREATE_A_REFERENCE` | owner/repo/ref=`refs/heads/minny/<variant-id>`/sha → ref |
| Commit rule file | `GITHUB_CREATE_OR_UPDATE_FILE_CONTENTS` | owner/repo/path/branch/message/base64 content; current file SHA if update → commit SHA |
| Open review | `GITHUB_CREATE_A_PULL_REQUEST` | owner/repo/title/body/head/base → PR number/URL |
| Reconcile existing PR | `GITHUB_LIST_PULL_REQUESTS` | owner/repo/head/base/state, pagination → candidate PRs; verify exact remediation marker |
| Read PR | `GITHUB_GET_A_PULL_REQUEST` | owner/repo/pull_number → merged flag, merged SHA, base/head, state |
| Inspect PR changes | `GITHUB_LIST_PULL_REQUESTS_FILES` | owner/repo/pull_number, pagination → changed paths/status |
| Update issue outcome | `GITHUB_UPDATE_AN_ISSUE` | owner/repo/issue_number/state plus validated fields → current issue |
| Find prior issue after timeout | `GITHUB_LIST_REPOSITORY_ISSUES` if present in pinned schema; otherwise Composio GitHub proxy GET `/repos/{owner}/{repo}/issues` | Page through results and match exact marker locally |
| Read Slack identity | `SLACK_TEST_AUTH` | selected connection → team/user identity |
| Channel picker | `SLACK_LIST_CONVERSATIONS` | pagination/type selection → channel IDs/state |
| Verify channel | `SLACK_RETRIEVE_CONVERSATION_INFORMATION` | channel ID → membership/archived metadata |
| Post thread/reply | `SLACK_CHAT_POST_MESSAGE` | channel/text; thread_ts for replies → channel and ts |
| Resolve permalink | `SLACK_RETRIEVE_MESSAGE_PERMALINK_URL` | channel/message timestamp → URL |
| Update own status message | `SLACK_UPDATES_A_SLACK_MESSAGE` | channel/ts/text → result; failure must not duplicate message |

Map semantic names into the exported schema: for example, Slack schemas can expose `channel` or `channel_id`, and list tools can expose cursor fields differently. The adapter owns that translation; application contracts never change to match a vendor rename. Validate `GITHUB_LIST_PULL_REQUESTS_FILES` and every listed slug during export; if unavailable, use a narrowly coded Composio proxy for the equivalent GitHub endpoint, retaining the same connection and authorization. Do not use a separate personal access token as an undisclosed fallback.

Provider proxy fallback is only for fixed app-coded relative paths/methods. Never pass model/browser URLs into it. Do not fetch an arbitrary returned URL with credentials; use the selected provider's content API.

## 7. Outbound lifecycle

### Gap issue

Create a remediation row and outbox operation when the baseline returns a complete evasion. Marker: `<!-- minny:remediation:<uuid> -->`. Title includes technique and short variant ID. Body includes synthetic label, hypothesis, rule version, actual miss result, 3-10 sanitized evidence references, why this is a detection gap, and Minny detail URL. Do not publish raw CSE source records or secrets. Mention the CSE finding via access-controlled Minny evidence links if applicable.

Issue creation is independent of Blue success: a failed proposal should leave a real tracked gap. Persist issue result immediately, then post the Slack root message and enqueue Blue analysis. Slack failure does not prevent analysis or PR creation.

### Proposal PR

After P2 validation passes:

1. Snapshot selected base branch SHA and read target file SHA at that revision.
2. Create deterministic branch `minny/<variant-uuid>` from base SHA.
3. Write only the allowed JSON rule file. For updates supply the existing blob SHA. A conflict requires re-read/revalidation, never force-push over human changes.
4. Create PR against the selected base branch. Record candidate file hash, commit SHA, validation corpus hashes, and proposal version.
5. PR body references “Related to #N”; **do not use `Closes #N` or `Fixes #N`**, which could close the gap on merge before detection verification.
6. Include before/after ES|QL, rationale, known-benign test counts, limitations, synthetic provenance, and instructions that merge triggers verification.
7. Reply in the Slack root thread with PR/evidence links. A human merges in GitHub; the app has no auto-merge tool.

### Verification outcome

Success: comment on the issue with merged SHA, rule hash, event-set hash, matching event IDs, and replay timestamp; then close it via Composio and reply/update Slack. The product marks detection success before notifications, but displays pending/failed notification delivery independently.

Failure: leave the issue open; comment with the exact failed check; reply in Slack; retain `verification_failed`. Do not label a provider outage as “the patch failed to detect.” Distinguish invalid rule, missing telemetry, complete miss, and infrastructure error.

## 8. Inbound event setup and handler

Primary trigger candidate: `GITHUB_PULL_REQUEST_EVENT`, catalog-described as opened/closed/synchronized events. `GITHUB_PULL_REQUEST_STATE_CHANGED_TRIGGER` is a per-PR alternative. Do not assume GitHub-native payload fields are copied unchanged by Composio.

Before creation:

```python
trigger_type = composio.triggers.get_type("GITHUB_PULL_REQUEST_EVENT")
# Save trigger_type.config and trigger_type.payload to the vendor contract files.
```

Build the configuration from the exported schema. The conceptual requirements are selected owner/repository and close/merge-capable events; use an actions filter only if actually supported. Then create with `slug`, server-derived `user_id`, explicit `connected_account_id`, and validated `trigger_config`. Store `trigger_id` with destination revision. [Trigger creation](https://docs.composio.dev/docs/setting-up-triggers/creating-triggers).

Register the project webhook:

```python
subscription = composio.triggers.set_webhook_subscription(
    webhook_url=f"{settings.public_base_url}/webhooks/composio"
)
# Store the returned secret in secret configuration, not logs or source control.
```

For local testing, use the documented signed forwarding command:

```sh
composio dev triggers listen --forward "http://localhost:8000/webhooks/composio"
```

The CLI and app must use the same `COMPOSIO_WEBHOOK_SECRET`. Production requires a publicly reachable HTTPS URL. Use SDK parsing on the **raw body** with signature verification; it also handles normalized payloads. [Webhook reception](https://docs.composio.dev/docs/setting-up-triggers/subscribing-to-events).

Handler contract:

1. Limit request body to 1 MiB; reject oversized 413.
2. Read bytes once and call `composio.triggers.parse(body=raw, headers=request.headers, verify_secret=secret)`.
3. Invalid signature/stale signed timestamp → 401; malformed body → 400. Never acknowledge unauthenticated events as valid.
4. Identify delivery ID, trigger ID, connected account and Composio user from the verified envelope. Match stored trigger/connection/workspace; mismatches are rejected/audited.
5. Insert durable inbox row and verification job in one transaction. Duplicate ID + same body → 200 without new job; same ID + changed body → reject/audit. Database failure → 503 so delivery can retry.
6. Return 202 quickly, target under 2 seconds. Do not call OpenAI, Elastic, or GitHub while holding the webhook request open.
7. Unknown but authenticated event type → record ignored and return 200. Route account-expiration events separately.

### Merge verification job

Load remediation by stored repository ID and PR number, not by an issue number found in text. Through Composio, read the authoritative PR. Require `merged == true`, matching selected repository/base branch, matching tracked head/PR, nonempty merged commit SHA, and allowed changed rule paths. `closed` with `merged=false` means rejected. Ignore unrelated PRs.

Fetch merged file content at `merged_commit_sha`, not `main`, and require normal file content under the allowed prefix. Reject deletion, symlink/submodule, oversize file, invalid JSON, unsupported predicate, or changed rule identity requiring review. Produce `VerifiedMerge` for P1. P2 validates/replays and manages activation.

Measure actual trigger latency in the demo project. If delayed/missing, a reconciliation job checks tracked awaiting-merge PRs every 30 seconds for the first 10 minutes, then every 5 minutes. This still uses Composio for provider reads and the same verification function. Record `source=reconciliation`; do not claim a webhook fired when polling found the merge. A native GitHub webhook is not silently substituted.

## 9. Idempotency and partial failures

| Failure point | Recovery |
|---|---|
| Issue created but response lost | List/search exact remediation marker in selected repo; adopt its number; no blind create retry |
| Branch already exists | Read ref; verify expected ownership/commit lineage; reuse or pause conflict |
| File write uncertain | Read file at branch; compare expected content hash and commit state |
| PR create uncertain | List PRs by stored head/base and exact marker; adopt matching PR |
| Slack root response lost | Reconcile exact operation marker if authorized history available; otherwise `delivery_unknown` and manual retry control |
| Slack update fails | Retain known ts and surface failure; do not post another root |
| Duplicate merge webhook | Unique replay key suppresses second job |
| Worker dies during replay | Resume saved evaluation/job; frozen event set and rule hash unchanged |
| Account revoked | Pause writes, show reconnect action, do not use another person's account |
| Repo renamed | Resolve immutable repo ID, reverify accessible owner/name; pause if identity cannot be resolved |
| Destination changed during run | Continue only under still-valid original consent/destination snapshot; otherwise pause for review |

Avoid promising exactly-once external delivery. Guarantee durable intent, duplicate suppression where identity can be reconciled, and explicit uncertainty otherwise.

## 10. Acceptance tests

1. Two Minny users connect distinct GitHub accounts; neither can attach/use the other's connection ID.
2. Forged callback status/account/nonce never marks a connection active.
3. Declined OAuth returns a usable Settings page; expired attempt can restart.
4. Read-only GitHub permissions disable publication with a concrete message.
5. Slack private channel without access fails setup, not the full experiment.
6. Real issue, branch/file commit, PR, and Slack thread use the user's selected destinations.
7. PR closed unmerged does not replay or close the issue.
8. Human-modified merged rule is the one fetched/tested.
9. Unsigned, stale, duplicate, wrong-account, and unrelated-PR webhooks produce expected results.
10. Timeout-after-create fixture does not create duplicate GitHub artifacts.
11. Restart after inbox commit completes replay.
12. Replay success closes the issue; replay miss/error keeps it open.
13. Disconnect stops future writes and disables its trigger; historical evidence remains.

Deliverables: adapter modules, onboarding endpoints, schema exports, signed webhook handler, reconciliation job, outbox recovery, live test evidence with sanitized IDs/URLs, and a complete user walkthrough.

## 11. Gmail notification channel

The required Gmail feature uses the same connection isolation, destination consent, durable outbox, and independent notification status described above. See [Gmail technical addendum](08-GMAIL-NOTIFICATIONS.md) for scopes, recipient policy, event templates, account setup, and acceptance tests. Gmail has no merge/approval authority and requires no inbound mailbox trigger.
