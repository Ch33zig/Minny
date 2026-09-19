# Platform, identity, persistence, and shared contracts

Status: proposed specification. Owner: P1, with P4 owning infrastructure files.

## 1. Runtime topology

```text
Browser ──HTTPS/session cookie──> FastAPI /api/v1 + frontend static assets
                                      │
                                      ├── PostgreSQL: identity, state, jobs, outbox
                                      └── short Composio onboarding/resource calls
Worker ──claims jobs from PostgreSQL──> OpenAI / Elastic / Composio
Composio ──signed POST──> /webhooks/composio ──durable inbox──> Worker
API + worker + browser ──scrubbed observability──> Sentry
```

Use one API and one worker initially. Worker concurrency: two jobs globally, one state-mutating job per experiment. Give webhook ingestion and authentication normal HTTP service independent of experiment work. Never use FastAPI background tasks as the only durable execution mechanism.

Register API and webhook routes before mounting static files. `/api/v1/*` missing routes must return JSON 404, not `index.html`. `/health/live` checks the process only. `/health/ready` checks database reachability, current migration, and worker heartbeat younger than 45 seconds; vendor health is reported separately.

## 2. Identity and authorization

### App login is distinct from provider authorization

Composio connections do not authenticate a person to Minny. Implement invite-only accounts:

1. CLI creates a 32-byte random invitation, stores its SHA-256 hash, expiry (24 hours), and intended workspace/role if applicable. Raw token is displayed once to the operator.
2. User opens `/join?token=...`, submits email and password, and consumes the token atomically. Minimum password length 12, maximum 128; hash with Argon2id using the library's maintained defaults. Email is normalized for account lookup. Email ownership is not independently verified in this invitation-only MVP; do not claim it is.
3. Login verifies the hash and creates a random 32-byte opaque session token. Store only its SHA-256 hash in Postgres. Cookie: `HttpOnly`, `Secure` on HTTPS, `SameSite=Lax`, `Path=/`; host-only domain. Lifetime 12 hours; revoke on logout and password change.
4. Every unsafe browser request includes `X-CSRF-Token`, compared to a session-bound random value, and a same-origin `Origin` check. Derive the CSRF value as HMAC-SHA256(APP_SECRET_KEY, raw session token); store its hash, return the derived value from `/auth/me`, and never expose the session cookie to JavaScript. Login/registration also require allowed origin and rate limiting.
5. Rate limit login to 5 failures per account/IP pair per 15 minutes and 30 per IP; store counters centrally. Return the same generic error for unknown account and wrong password.
6. Password recovery is operator-issued one-use reset token in this MVP. Connected Gmail is for operational notifications; authentication/recovery email is still outside scope.

Roles: `owner` and `member`. Owners manage integrations, destinations, workflow automation consent, invitations, and external publication. Members view findings and run internal simulations. A member's test cannot borrow the owner's external-action identity: an owner must explicitly publish its resulting gap, at which point the publishing principal is recorded. For the fastest demo, the workspace owner runs the experiment.

Server-generated UUIDs identify all app entities. Composio user key is `minny:<environment>:<workspace_uuid>:<user_uuid>`, computed server-side. This encodes a membership identity; never accept it from the client. Workspace membership is checked on every data query and job. Every job stores its workspace and acting user. Losing membership disables future external operations.

### Workspace connection policy

One selected GitHub account, one selected Slack account, and one selected Gmail account per owner/workspace initially. Store the exact connected account ID, provider identity, and toolkit. OAuth tokens remain at Composio. No API key/token in HTML, local storage, logs, model prompts, or browser request bodies other than app login credentials.

Automation consent is explicit in Settings: “For experiments I start, create detection issues, rule PRs, and messages in these selected destinations; after I merge, verify and update those artifacts.” Save `policy_version`, actor, timestamp, repository ID, channel ID, and connection IDs. Changing a destination requires a new consent record. In-flight operations retain their original destination snapshot; never silently reroute them.

## 3. PostgreSQL model

All tables use UTC `timestamptz`, UUID primary keys unless noted, and workspace-scoped indexes. Enforce tenant ownership through composite foreign keys or equivalent transactional checks. JSONB never replaces authorization checks.

| Table | Required fields / constraints |
|---|---|
| `users` | id, normalized_email unique, password_hash, created_at, disabled_at |
| `workspaces` | id, name, created_at |
| `memberships` | workspace_id + user_id unique, role, created_at, revoked_at |
| `invites` | token_hash unique, expires_at, consumed_at, workspace_id nullable, role |
| `sessions` | token_hash unique, user_id, csrf_hash, expires_at, revoked_at |
| `connections` | workspace_id, user_id, toolkit, composio_user_id, connected_account_id unique, provider_identity JSONB, status, checked_at |
| `connect_attempts` | nonce_hash unique, workspace_id, user_id, toolkit, auth_config_id, expires_at, consumed_at |
| `destinations` | workspace_id, user_id, github_connection_id, repo_id, owner, repo, base_branch, rule_prefix, slack_connection_id, team_id, channel_id, trigger_id, revision |
| `notification_policies` | workspace_id, user_id, channel `slack/gmail`, connection_id, enabled, event_types, recipients JSONB for Gmail, revision, consent timestamp |
| `notification_deliveries` | remediation_id, event_id, channel, policy_revision, recipient, outbox_key unique, status, provider_message_id, provider_thread_id, error, sent_at |
| `automation_consents` | principal, immutable destination snapshot, policy_version, enabled, accepted_at, revoked_at |
| `datasets` | workspace_id, source_name, file_sha256, parser_version, manifest JSONB, raw/valid/quarantined counts, status |
| `findings` | workspace_id, dataset_id, title, who/what/when/how JSONB, evidence_refs JSONB, confidence label, alternatives, rule_id nullable |
| `experiments` | workspace_id, actor_id, technique_id, persona, stage, version integer, current_variant_id, parent_experiment_id nullable, stop_requested, error JSONB |
| `variants` | experiment_id, sequence, parent_variant_id nullable, plan JSONB, seed, base_time, compiler_version, events JSONB, event_set_sha256, validation JSONB; immutable after validation |
| `experiment_events` | experiment_id + sequence unique, event_type, experiment_version, payload JSONB, created_at; insert with state change in one transaction |
| `agent_messages` | experiment_id, sequence unique within experiment, sender, recipient, kind, summary, evidence_refs, structured_payload, model/request IDs, token usage |
| `evaluations` | variant_id, kind `baseline/candidate/merged/regression`, event_set_sha256, rule_set_sha256, commit_sha nullable, status, matching_event_ids, metrics, evidence, error |
| `rule_revisions` | workspace_id, rule_id, content_sha256, file_path, source_commit, rule JSONB, validation status |
| `remediations` | workspace_id, variant_id, destination snapshot, stage, issue_number/url, branch, pr_number/url, candidate_hash, merged_sha, replay_evaluation_id, version |
| `rule_activations` | workspace_id, repo_id, rule_id, active_revision_id, activated_at, superseded_by nullable |
| `jobs` | kind, workspace_id, principal_id, aggregate_id, payload, idempotency_key unique, status, attempts, available_at, lease_owner, lease_until, heartbeat_at |
| `outbox` | logical_key unique, operation, destination snapshot, request_hash, status `pending/running/succeeded/uncertain/failed`, provider_result, attempt count |
| `webhook_inbox` | provider_delivery_id unique, payload_hash, normalized_payload, received_at, status, rejection_reason |
| `audit_events` | workspace_id, actor, operation, resource IDs, result, request_id, timestamp; no secrets/raw OAuth URL |

For MVP event sets, cap each variant at 200 synthetic events and 1 MiB canonical serialized JSON. Store the exact set in Postgres; mirror searchable documents into Elastic. Large CSE raw datasets remain in the operator's source archive, with normalized records and `event.original` in Elastic. Postgres stores the file manifest, not the whole source file.

## 4. Experiment and remediation state

An experiment tracks computation; a remediation tracks external workflow. Do not overload a single `detected` boolean.

Experiment `stage`:

```text
queued → planning → validating → ingesting → evaluating
    → detected
    → evaded
    → failed
Any active stage → cancelled (at the next safe boundary)
```

Validation may return to planning at most twice. A detected experiment can enqueue a new experiment/variant if the user enabled mutation; it does not change its historical result. An evaded experiment remains evaded historically even when its remediation succeeds.

Remediation `stage`:

```text
gap_confirmed → opening_issue → proposing → validating_fix
→ opening_pr → awaiting_merge → verifying_merge → loading_rule
→ replaying → remediated
```

Persist `resume_stage` when entering a recoverable paused state; resume only after rechecking consent and destination capabilities. Alternative states: `needs_connection`, `needs_review`, `rejected` (PR closed unmerged), `verification_failed`, `failed`, `cancelled`. Slack and Gmail delivery statuses are separate and cannot turn a successful replay into a failed detection. A rule may be valid but require human review if its false-positive evidence is insufficient.

Use compare-and-swap updates on `version`; state update plus next job/outbox insert happen in one database transaction. Ignore stale job completions. Save the allowed transition map and reject impossible transitions with `STATE_CONFLICT`.

## 5. Durable job execution and retries

Claim eligible jobs using `FOR UPDATE SKIP LOCKED`, set a 120-second lease, commit, then perform work outside the transaction. Heartbeat every 15 seconds. Every aggregate state write verifies the job lease/fencing token and expected version. The scheduler reclaims expired jobs. Provider side effects cannot be made exactly-once by database locking; reconcile uncertain calls before retrying.

Retry read-only provider calls on network failures, 429, and transient 5xx: at most 3 total attempts, exponential delays 2/4 seconds plus jitter, honor a longer `Retry-After`. Do not automatically retry 400/401/403. Refresh connection status on auth failures and mark `needs_connection` where appropriate.

Write timeouts are `uncertain`, not failed. Use deterministic branch names, issue/PR markers, and saved operation IDs to find already-created artifacts. If Slack posting cannot be reconciled with granted scopes, leave `delivery_unknown` for operator review rather than resending blindly.

Defaults: HTTP provider request timeout 30 seconds, OpenAI stage timeout 90 seconds, Elastic ingest timeout 60 seconds, total experiment active compute budget 10 minutes. Waiting for a human merge is not charged against active compute. Max one external issue/PR per variant per destination; replay key includes variant + merged commit + rule content hash.

## 6. Shared types

Contract version is `1`. JSON property names use snake_case. IDs are opaque strings externally and UUIDs internally. Dates are ISO 8601 UTC. No frontend code infers IDs from array indices.

```typescript
type EvaluationStatus = "detected" | "evaded" | "error";
type EvaluationResult = {
  schema_version: 1;
  evaluation_id: string;
  experiment_id: string;
  variant_id: string;
  event_set_sha256: string;
  rule_set_sha256: string;
  commit_sha: string | null;
  status: EvaluationStatus;
  matched_rule_ids: string[];
  matched_synthetic_event_ids: string[];
  matched_background_event_ids: string[];
  ingestion_complete: boolean;
  query_complete: boolean;
  evidence: Array<{event_id: string; index: string; document_id: string}>;
  error: {code: string; message: string; retryable: boolean} | null;
};
type VerifiedMerge = {
  schema_version: 1;
  workspace_id: string;
  remediation_id: string;
  variant_id: string;
  repository_id: number;
  pull_number: number;
  base_branch: string;
  merged_commit_sha: string;
  changed_rule_paths: string[];
  source: "composio_trigger" | "reconciliation";
};
```

P2 implements `evaluate(variant_id, rule_revision_ids, kind) -> EvaluationResult`, `retrieve_evidence(workspace_id, filters) -> EvidencePage`, `validate_candidate(variant_id, rule_document) -> CandidateReport`. P1 implements `enqueue_replay(VerifiedMerge) -> job_id`. P3 implements `publish_gap(remediation_id)`, `publish_proposal(remediation_id, rule_document)`, `finalize_remediation(remediation_id, evaluation_id)`. All implementations load authorized workspace/destination state from the database rather than trusting model-provided credentials or URLs.

`CandidateReport` contains syntax_ok, positive_variant_detected, known_positive_regressions, known_benign_matches/count, unclassified_matches/count, disallowed_features, evidence_refs, and decision `pass/revise/needs_review/error`.

## 7. HTTP contract

Prefix `/api/v1`. JSON, UTF-8. Lists use opaque `cursor`, default limit 50, maximum 200. Error envelope: `{"error":{"code":"...","message":"...","retryable":false,"request_id":"...","details":{}}}`. Unauthorized 401; forbidden 403; missing scoped resource 404; conflicting state/idempotency payload 409; validation 422; upstream unavailable 503.

| Method/path | Input | Output / behavior |
|---|---|---|
| GET `/public-config` | none | environment, release, browser Sentry DSN only; no secret fields |
| POST `/auth/register` | invite_token, email, password | 201 user + session cookie |
| POST `/auth/login` | email, password | 200 user + session cookie |
| POST `/auth/reset` | one-use operator-issued reset_token, new_password, allowed origin | 204; consume reset token and revoke old sessions |
| POST `/auth/logout` | CSRF header | 204; revoke session |
| GET `/auth/me` | session | user, memberships, csrf_token |
| POST `/workspaces` | name | 201 workspace; caller owner |
| GET `/workspaces/{w}/setup` | membership | connection, destination, dataset, provider capability statuses; explicit blocking reasons |
| GET `/workspaces/{w}/integrations` | membership | sanitized connections; no tokens |
| POST `/workspaces/{w}/integrations/{toolkit}/connect` | owner; toolkit github/slack/gmail | 201 attempt_id, redirect_url, expires_at |
| GET `/integrations/composio/callback` | nonce, status, connected_account_id | validated attachment then 303 `/settings/integrations` |
| DELETE `/workspaces/{w}/integrations/{connection_id}` | owner | 202 disconnect job, pause dependent actions |
| GET `/workspaces/{w}/github/repositories` | owner; cursor | accessible repo IDs, names, permissions, default branches |
| GET `/workspaces/{w}/slack/channels` | owner; cursor | channel IDs/names and usable flag |
| PUT `/workspaces/{w}/destinations` | repo_id, base_branch, rule_prefix, channel_id, revision | verify through provider; 200 snapshot or 409 |
| POST `/workspaces/{w}/destinations/test` | owner, test_kind read/write | job; write test explicitly posts labeled test artifacts |
| PUT `/workspaces/{w}/notification-policy` | owner, channel, enabled, connection_id, recipients, event_types, revision | validated consent/policy revision |
| POST `/workspaces/{w}/notifications/test` | owner, channel, policy_revision; Idempotency-Key | 202 labeled test notification; one queued delivery per recipient |
| GET `/workspaces/{w}/notifications` | owner; cursor | sanitized per-channel delivery history |
| POST `/workspaces/{w}/notifications/{id}/retry` | owner, duplicate_risk_acknowledged for uncertain sends; Idempotency-Key | 202 audited retry, never silently duplicate |
| PUT `/workspaces/{w}/automation-policy` | enabled, accepted_policy_version, destination_revision | immutable consent snapshot |
| GET `/workspaces/{w}/techniques` | membership | supported techniques, prerequisites, current aggregate state |
| POST `/workspaces/{w}/experiments` | technique_id, persona, source_finding_id nullable, mutate_after_detection=false | 202 experiment_id, job_id, status_url |
| GET `/workspaces/{w}/experiments/{e}` | membership | state, variant, evaluations, remediation, agent summaries, sequence |
| GET `/workspaces/{w}/experiments/{e}/events` | after_seq integer | incremental persisted state events, next_seq |
| POST `/workspaces/{w}/experiments/{e}/stop` | actor/owner | 202; checkpoint cancellation |
| POST `/workspaces/{w}/remediations/{r}/publish` | owner + consent | 202; bind external-action principal |
| POST `/workspaces/{w}/remediations/{r}/reconcile` | owner | 202; provider verification, never pretend merge |
| GET `/workspaces/{w}/findings` | filters/cursor | provenance-backed CSE findings |
| GET `/workspaces/{w}/evidence/{event_id}` | membership | normalized record, original source reference |
| GET `/workspaces/{w}/datasets` | membership | manifests and parser/ingestion status |
| GET `/workspaces/{w}/coverage` | membership | per-technique tested variants/open gaps/revision timestamps |
| POST `/webhooks/composio` (no API prefix) | signed raw body | persist inbox and enqueue; 202, duplicate 200 |

All experiment/publish/reconcile POSTs require `Idempotency-Key`; store workspace + route + key + canonical request hash + response for 24 hours. Same key/body returns original response; same key/different body returns 409. The frontend generates and retains the key across network retries.

No arbitrary URL ingestion endpoint or arbitrary ES|QL execution endpoint is exposed to browsers. CSE import is operator CLI initially, with authorized dataset selection in UI. Model tools use internal narrow functions, not browser routes with administrative credentials.

## 8. Coverage and isolation

Coverage means observed detection of tested variants under a stated rule revision, not a guarantee that a technique is fully defended. A cell stays red if any tested variant has an unresolved gap. Green requires at least one evaluated variant, no unresolved tested gaps, and a successful current-revision evaluation. Changing rules marks prior coverage stale until relevant regression runs finish. Unsupported techniques stay disabled/untested.

Always derive totals from distinct technique/variant IDs; never increment a browser counter. API responses include `as_of`, `rule_set_sha256`, and test counts.

Use workspace-specific Elastic indices. Runtime reads name only indices resolved from authenticated workspace data. Never interpolate user/model-supplied index names. All provider destinations are selected from verified resource IDs.

If retaining a separate static-site host: explicitly allow that exact HTTPS origin, enable credentials, allow CSRF and Sentry headers, use a same-site custom domain where possible, and test browser cookie restrictions. The default same-origin deployment avoids this extra dependency.
