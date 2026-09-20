# Setup runbook, four-person delivery plan, and acceptance gates

This is a build specification. The commands for Minny modules, Compose, migrations, and tests are required deliverables to implement, not commands that already work in the current static repository. Do not provision paid infrastructure or send test artifacts until the team supplies its accounts and chooses the destinations.

## 1. Service/account checklist

| Service | Owner | Setup output | Verification gate |
|---|---|---|---|
| GitHub source | P1 | Four collaborator accesses, protected main if available, branch naming | Each builder can create a feature branch and PR |
| OpenAI | P1 | API project, billing/credits, project key, accessible model | Real structured response and tool continuation |
| Elastic | P2 | Cloud Hosted deployment, ES/Kibana URLs, version, operator and restricted keys | Mapping + bulk + complete ES|QL query |
| CSE | P2 | Dataset from sponsor, local raw archive, source manifest | Parser mapping based on actual data, evidence-backed finding |
| Composio | P3 | Dev/demo projects, managed auth configs, pinned versions, signing secret | Two-user connection test and real signed trigger |
| Detection repository | P3 | Selected repo ID, base branch, initial rules | Issue + branch + file commit + PR all work |
| Slack | P3 | Authorized workspace, selected test channel, app access | Test root/reply/permalink works |
| Gmail | P3 | Managed OAuth auth config, user-authorized sender, recipient policy | Test send; revoke/timeout recovery; no mailbox read required |
| Sentry | P4 | Browser/Python projects, DSNs, release | Trace + Replay visible, sensitive data absent |
| Runtime | P4 | API web service, worker, Postgres, HTTPS origin | Restart recovery, callback/webhook publicly reachable |

Team accounts provision service infrastructure; product users only need a Minny invite and their own GitHub/Slack/Gmail authorization. Elastic and OpenAI are operator-managed for this MVP. User-supplied Elastic/OpenAI credentials are not part of the Settings flow.

## 2. Required service manifest

Commit `docs/service-manifest.json` with environment name, app release, selected runtime versions, Elastic version, redacted endpoint hostnames where appropriate, Composio toolkit versions/schema hashes, auth config identifiers, Sentry project identifiers, callback path, webhook path, tested_at, and per-capability test outcome. Do not include keys, webhook secrets, raw OAuth links, passwords, or full test payloads with private data.

Exact package versions are resolved and locked in the first build slice after compatibility tests; do not make an unverified version number a contractual dependency. CI must use the committed locks. Record changed versions and rerun vendor contract tests before updates.

## 3. Bootstrap repository and local runtime

P1 creates the backend package and dependency lock. P4 creates frontend build, Docker configuration, and Compose. No builder independently creates another root manifest.

Python dependencies: FastAPI, uvicorn, Pydantic 2, pydantic-settings, SQLAlchemy 2, psycopg 3, Alembic, httpx, openai, composio, sentry-sdk, argon2-cffi. Dev: pytest, pytest-asyncio, respx, ruff. Use httpx for the narrow Elastic REST adapter so Elasticsearch client-version coupling is avoided. Synchronous vendor SDK calls run in a thread pool/worker, never block an async API event loop.

Browser dependencies: `@sentry/browser`; development: esbuild and Playwright. Tests may use the browser runner directly; no frontend framework is required.

Required repository commands after the bootstrap PR:

```sh
# In the cloned Minny repository; use the committed lock after initial bootstrap.
uv sync --frozen
npm ci
npm run build
docker compose up -d postgres
uv run alembic upgrade head
uv run python -m backend.cli invite --role owner
uv run uvicorn backend.main:app --host 127.0.0.1 --port 8000
# Separate terminal:
uv run python -m backend.worker
```

The invite command prints a one-use link; account setup occurs through the browser. No default shared password or hard-coded user ID.

Compose service requirements: PostgreSQL 16 with persistent named volume and `pg_isready` healthcheck; local port 5432; credentials from an untracked local environment file. API/worker can run on host for development. Optional Compose API/worker services use the same image and service-name DB host. Clarify host `localhost` versus container `postgres` in README; wrong DB hostname must produce a clear readiness error.

P4's Docker image uses Python 3.12 runtime and a Node 22 build stage. Copy locked dependencies, build frontend, copy `dist/`, run as a non-root user, and expose port from `PORT`. Do not bake `.env`, dataset archives, API keys, or local research files into the image. `.dockerignore` excludes them. API command is `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`; worker command is `python -m backend.worker`.

## 4. Environment and secret ownership

Use the included `environment.example` as a field inventory; all secret blanks must be filled through local secret configuration or hosting secret fields. Startup validates fields by capability. Missing OpenAI/Elastic credentials prevent live experiments; missing Composio prevents publication but not local fixtures. `APP_ENV=demo` never substitutes fixture results for unavailable providers.

| Variable | Who consumes it | Source / meaning |
|---|---|---|
| `APP_ENV`, `PUBLIC_BASE_URL`, `RELEASE` | API/worker/browser public config subset | development/demo, exact HTTPS origin, Git SHA |
| `DATABASE_URL` | API/worker/migration | Postgres connection string; TLS in hosted runtime |
| `APP_SECRET_KEY` | API | Cryptographically random 32+ bytes; CSRF derivation/session-related signing |
| `OPENAI_API_KEY`, `OPENAI_MODEL` | Worker; setup CLI | API project key/model |
| `ELASTICSEARCH_URL` | Worker/setup | Elasticsearch endpoint, not Kibana |
| `ELASTIC_QUERY_API_KEY`, `ELASTIC_INGEST_API_KEY` | Worker | Restricted encoded API-key credentials |
| `ELASTIC_BOOTSTRAP_API_KEY` | Local setup only | Operator privilege; never deployed to API/worker |
| `COMPOSIO_API_KEY` | API/worker/setup | Project-specific server credential |
| `COMPOSIO_AUTH_CONFIG_GITHUB`, `COMPOSIO_AUTH_CONFIG_SLACK`, `COMPOSIO_AUTH_CONFIG_GMAIL` | API | Managed auth blueprint IDs |
| `COMPOSIO_TOOLKIT_VERSION_GITHUB`, `COMPOSIO_TOOLKIT_VERSION_SLACK`, `COMPOSIO_TOOLKIT_VERSION_GMAIL` | API/worker | Tested dated versions |
| `COMPOSIO_WEBHOOK_SECRET` | API/local forwarder | Returned by subscription/CLI; no browser access |
| `SENTRY_BACKEND_DSN` | API/worker | Python project ingestion endpoint |
| `SENTRY_WEB_DSN` | Public config | Browser project ingestion endpoint |
| `SENTRY_AUTH_TOKEN`, `SENTRY_ORG`, `SENTRY_PROJECT` | Build only if uploading source maps | Never runtime browser token |
| `MAX_ACTIVE_EXPERIMENTS`, `MAX_LLM_CALLS`, `MAX_TOOL_CALLS`, `MAX_TOTAL_TOKENS` | Worker | Application budgets |
| `CSE_DATA_DIR` | Operator CLI only | Local authorized source archive |

Do not put per-user connected account IDs, repository IDs, channel IDs, or user credentials in global environment variables. They belong to workspace/user database rows. This is essential for real user onboarding.

## 5. Hosted deployment runbook

Proposed default: Render with web and worker using the same repository commit/image, plus managed Postgres in the same region. Select service plans that support an always-available worker and the required database persistence; check account pricing/credits before creation. This package makes no free-tier availability promise. Render documents FastAPI web deployment and background-worker services. [FastAPI deployment](https://render.com/docs/deploy-fastapi), [background workers](https://render.com/docs/background-workers).

1. Build and test the container locally; confirm `dist/` is included and API routes take precedence.
2. Provision Postgres; populate environment secrets separately for API and worker according to table above.
3. Create web service and worker from the same commit. Set `/health/ready` as readiness endpoint; the live endpoint must not expose configuration.
4. Run `alembic upgrade head` once as a deployment step before starting the new application version. Do not have all worker instances race migrations.
5. Set `PUBLIC_BASE_URL` to the actual HTTPS origin. Configure trusted proxy handling correctly for secure cookies; never trust arbitrary forwarded headers from the public internet.
6. Create the demo invitation through an operator shell/one-off job; complete login in the hosted browser.
7. Register Composio callback URL and project webhook URL for this origin. Capture its signing secret; deploy it before enabling triggers.
8. Connect accounts from the hosted app, choose the repository/channel, and run capability tests. A local account connection is not proof that the deployed callback works.
9. Import a bounded CSE slice and run baseline/candidate live checks from the deployed worker.
10. Verify Sentry release/environment, browser Replay, API spans, and worker spans.
11. Restart API and worker during an active queued test. Confirm state and queued verification survive.
12. Complete the real merge replay and save evidence links.

Local fallback for a demo if hosting is not ready: run API + worker + Postgres on one reliable machine, expose the API using a HTTPS tunnel, update `PUBLIC_BASE_URL` and the Composio webhook, and rerun the callback/webhook tests. Tunnel URL changes invalidate old callback configuration; do not assume a tunnel survives laptop sleep. Label this local hosted demo accurately.

Existing Sites hosting metadata is not changed by these drafts. Publishing the existing frontend through Sites remains a separate deployment action; using a separate frontend origin requires document 01's cross-origin work. The core API/worker cannot be inferred from a static hosting deployment.

## 6. Provisioning scripts to implement

| Script/command | Behavior | Success output |
|---|---|---|
| `backend.cli doctor` | Validate config, DB/migration/worker, read-only provider probes | Per-capability pass/fail, no secrets |
| `backend.cli invite --role owner` | One-time registration invitation | URL displayed once, expiry |
| `scripts/elastic/bootstrap.py --workspace <uuid>` | Create strict mappings/indices and restricted key guidance | Index list and mapping hashes |
| `backend.cli dataset profile --path <local-path>` | Read/archive manifest, infer candidate field mapping | Counts/format/uncertainties; no ingestion |
| `backend.cli dataset ingest --workspace <uuid> --manifest <path>` | Validate selected parser and bulk index | Imported/quarantined counts + source hash |
| `backend.cli dataset replay --workspace <uuid> --dataset <uuid> --batch-size 100` | Paced import + detection windows; durable cursor | Replay ID and progress |
| `scripts/composio/export_contracts.py` | Fetch pinned selected schemas/types | Schema files/hashes; no account secrets |
| `backend.cli integrations verify --workspace <uuid>` | Read checks for selected accounts/resources | Capabilities and specific missing grants |
| `backend.cli webhooks configure` | Explicitly register current project URL | URL/subscription ID; secret routed to operator secret store |
| `backend.cli demo seed --workspace <uuid>` | Add approved templates/known benign fixtures, no fake provider success | Seed manifest/hashes |
| `backend.cli demo verify --workspace <uuid>` | Read evidence of gates, identify incomplete capabilities | Machine-readable acceptance report |

No script should print provider keys, full account-state objects, authorization headers, or entire webhook bodies into ordinary logs. Fixture mode requires explicit `--fixtures`; it cannot run under the same label as a live provider acceptance test.

## 7. Parallel delivery tickets

These are scoped acceptance tickets, not completed implementation. Estimates are rough person-hours and assume familiarity with the stack; vendor access and CSE analysis may dominate. The full functional scope is aggressive for a hackathon, so use the cut lines below rather than weakening correctness.

### P1: OpenAI/Huawei/platform

| Ticket | Files | Output | Acceptance | Estimate |
|---|---|---|---|---|
| A1 Foundation | `backend/main.py`, settings, database, migrations, `contracts/` | HTTP skeleton, models, fixture contracts | Health + validated example payloads | 1-2 h |
| A2 Identity | `backend/core/auth.py`, sessions, memberships, API auth | Invite/login/session/CSRF/workspace | Two users cannot cross workspace; logout revokes | 2-3 h |
| A3 Durability | `backend/core/jobs.py`, worker, state, outbox models | Leased jobs, persisted stage transitions | Restart and duplicate job tests | 2-3 h |
| A4 Simulation | `backend/simulation/` | Plan compiler/validator/templates | Deterministic hash, invalid-parent rejection | 2-3 h |
| A5 Agents | `backend/agents/` | OpenAI roles, tool loop, budgets | Critic + Blue revisions from actual tool feedback | 3-4 h |
| A6 Integration | `backend/api/`, orchestrator | Start/read/stop/publish/replay APIs | Complete frozen-variant replay | 2-3 h |

P1 is the critical-path owner. P3 supplies connection-route implementations; P4 supplies deployment files. P1 only registers those routers and merges shared schema/migration requests; do not make P1 implement every vendor integration.

### P2: Elastic/CSE

| Ticket | Files | Output | Acceptance | Estimate |
|---|---|---|---|---|
| B1 Elastic setup | `scripts/elastic/`, detection client/mappings | Live indices and restricted keys | Bulk/read/query pass | 1-2 h |
| B2 CSE profile/parser | `backend/data/`, manifest | Actual schema/provenance mapping | Round-trip to original record; quarantine malformed | 2-4 h |
| B3 Investigation | queries, findings doc | At least one supported finding | Who/what/when/how with evidence | 2-4 h |
| B4 Rule evaluator | `backend/detection/`, fixtures | Predicate compiler, complete result semantics | Miss/catch/background-only/error tests | 2-3 h |
| B5 Validation/replay | candidate/regression/revisions | Actual merged-rule loading and validation | Changed merged content tested, no older activation | 2-3 h |
| B6 Stream replay | `backend/data/replay.py` | Cursor/window/dedup detection | Restart without repeated findings | 1-2 h |

### P3: Composio

| Ticket | Files | Output | Acceptance | Estimate |
|---|---|---|---|---|
| C1 Schema/accounts | scripts, vendor schemas | Auth configs, pins, selected tool contract | Required tools and trigger schema captured | 1-2 h |
| C2 User onboarding | workflow connections/resources/router | Connect callback + destination validation | Two-user OAuth isolation; denied/cancelled recovery | 2-3 h |
| C3 Publication | workflow GitHub/Slack/outbox adapters | Issue, branch/file, PR, message thread | Real artifact links and retry reconciliation | 2-4 h |
| C4 Inbound | webhook/parser/merge verifier | Signed inbox and VerifiedMerge | Closed-unmerged ignored; duplicate suppressed | 2-3 h |
| C6 Gmail | `backend/workflows/gmail.py`, notification policy/delivery adapter | User-configurable operational emails through Composio | Gmail addendum G01-G10 pass | 2-3 h |
| C5 Recovery | reconciler/disconnect/finalize | Reconnect/partial delivery/final outcomes | Gap closed only after detection success | 2-3 h |

### P4: Frontend/Sentry/deployment

| Ticket | Files | Output | Acceptance | Estimate |
|---|---|---|---|---|
| D1 Build/UI modules | `frontend/`, Node config | Existing visuals preserved, API client | Builds to `dist/`, fixtures render | 1-2 h |
| D2 Login/settings | views login/integrations | Real connect/select/test UX | Hosted OAuth round trip, accurate errors | 2-3 h |
| D3 Dashboard/evidence | views/components | Live stages, investigation, workflow links | Refresh restores state; no fake metrics | 2-3 h |
| D4 Observability | browser + backend helper | Tracing/Replay/scrubbing | Real trace/replay plus redaction check | 1-2 h |
| D5 Deployment | `infra/`, Docker, build config | API/worker/Postgres topology | Public webhook + restart test | 2-3 h |
| D7 Gmail UI | integrations/settings and notification history | Sender/recipient/events/test/reconnect | Policy edits and uncertain-send state render correctly | 1-2 h |
| D6 Demo/QA | Playwright and demo docs | Whole-flow test + observed Sentry improvement | Evidence checklist and live rehearsal | 2-3 h |

## 8. Merge order and checkpoints

**First 45 minutes:** freeze contracts, repo file ownership, service choices, paths, enums, and one technique template. P1 merges scaffold/contracts; others work against fixtures immediately. Provision account access in parallel.

**Checkpoint 1:** dashboard → real API → durable job → fixture result. All teams share UUIDs and errors. Label fixtures visibly.

**Checkpoint 2:** P2 proves live Elastic ingestion and miss/catch; P1 proves real OpenAI plan/critique/tool use; P3 proves real hosted user connection and issue/PR; P4 proves deployed callback and Sentry traces. These independent proofs expose vendor blockers early.

**Checkpoint 3:** real generated variant → Elastic miss → gap issue → validated proposal → PR. Never postpone merging interfaces until demo time.

**Checkpoint 4:** human merge → signed event/reconciliation → actual merged file → exact saved variant replay → result → issue/Slack update.

**Final checkpoint:** CSE findings and stream replay integrated; Sentry improvement evidence captured; two full rehearsals, including one restart and one negative path.

Reserve the final 4 hours for integration, live credentials, evidence, and demo. Do not use that window to add another technique or integration.

Cut order if behind: extra personas → second technique → optional review-comment agent → source-map automation → sophisticated animations. Keep user identity isolation, honest error semantics, exact replay, real CSE findings, real provider workflow, and the two Sentry products. If a required track capability cannot be completed, disclose that gap; do not replace it with an unlabeled simulation.

## 9. Acceptance matrix

All tests record release, environment, input fixture/hash, expected result, actual result, and evidence. Unit tests use fixtures; live tests use actual connected accounts. Separate `unit`, `integration`, `live`, and `e2e` test markers.

| ID | Input/condition | Required result | Owner |
|---|---|---|---|
| T01 | Same start request retried | One experiment, same response | P1 |
| T02 | Same idempotency key, changed body | 409, no second operation | P1 |
| T03 | Cross-workspace resource ID | 404/403, no provider call | P1/P3 |
| T04 | Expired/revoked session | 401, no mutation | P1 |
| T05 | Missing/invalid CSRF | Rejected before mutation | P1 |
| T06 | Compiler repeat with same inputs | Identical events/hash | P1 |
| T07 | Missing/cyclic process ancestry | Validation rejection | P1 |
| T08 | LLM refusal/bad schema | Typed failure, no fabricated plan | P1 |
| T09 | Agent budget reached | Stop without new calls | P1 |
| T10 | Critic/Blue negative feedback | Persisted revision or needs_review | P1/P2 |
| T11 | Bulk item failure under HTTP 200 | Error, never evasion | P2 |
| T12 | Ingested docs not searchable yet | Wait/barrier, no premature result | P2 |
| T13 | Only background matches | Attack not detected | P2 |
| T14 | Partial/invalid/truncated query | Error/incomplete, never evasion | P2 |
| T15 | Baseline vs variant vs fix | Controlled miss then catch | P2 |
| T16 | Candidate matches benign fixture | Revise/review, no validated PR | P1/P2 |
| T17 | Unclassified CSE match | Labeled unclassified, no false-positive claim | P2 |
| T18 | CSE finding | Exact source hash/line evidence resolves | P2 |
| T19 | CSE replay restart/overlap | No skipped committed cursor or duplicate finding | P2 |
| T20 | OAuth callback forged/reused/expired | No attached account | P3 |
| T21 | Valid OAuth, insufficient repo rights | Explicit capability error | P3/P4 |
| T22 | Slack inaccessible private channel | Setup failure, no hidden alternate destination | P3 |
| T23 | Issue/PR create timeout after success | Adopt existing artifact or explicit uncertainty | P3 |
| T24 | Invalid/stale webhook signature | 401; no job | P3 |
| T25 | Duplicate valid webhook | One replay job | P3/P1 |
| T26 | PR closed without merge | Rejected, no replay | P3 |
| T27 | Wrong repo/base/connection event | Ignored/rejected with audit | P3 |
| T28 | Human modifies rule in PR | Actual merged content tested | P2/P3 |
| T29 | Concurrent merged rules | No older revision replacing newer active one | P1/P2 |
| T30 | Replay succeeds but Slack fails | Detected/remediated + delivery warning | P3/P4 |
| T31 | Replay fails | Issue stays open, no green cell | P2/P3/P4 |
| T32 | Worker dies after persisted intent | Job recovers without duplicate artifacts | P1/P3 |
| T33 | Page refresh/workspace switch | Correct authoritative state; no old data flash | P4 |
| T34 | Hostile log HTML | Rendered as text | P4 |
| T35 | Repeated technique test | Distinct-count coverage, no inflation | P1/P4 |
| T36 | Tracing + Replay | Real data in Sentry, linked run context | P4 |
| T37 | Secret-bearing login/callback/evidence | No secrets/raw records in sampled Sentry payloads | P4 |
| T38 | Disconnect after job queued | No new external write under revoked consent | P1/P3 |
| T39 | Missing webhook delivery | Composio reconciliation finds merge, labeled source | P3 |
| T40 | Full deployed run and human merge | Real artifact trail and before/after detection evidence | All |

Required test commands after implementation: `uv run pytest -m 'not live'`, `npm run test:e2e`, and `uv run pytest -m live` only against explicitly configured test destinations. A green unit suite does not certify account scopes or live trigger support.

## 10. Demonstration sequence and sponsor evidence

1. Briefly show user-connected repository/channel and ready checks.
2. Show one real CSE finding with source evidence.
3. Run one supported synthetic experiment; show a real agent revision/tool result.
4. Show Elastic telemetry and complete baseline miss.
5. Open the real issue, Slack thread, and validated PR.
6. Human merges in GitHub.
7. Show the merged SHA loaded and frozen event-set hash reused.
8. Show real matching Elastic evidence, coverage update, and issue/Slack remediation status.
9. Briefly show the real Sentry trace/replay and the improvement it informed; explain a concrete Codex contribution.

Keep a saved successful run for browsing if a provider is temporarily unavailable, clearly labeled as recorded evidence. Do not animate an offline fixture as a new live run.

## 11. Unresolved external facts and close-out gates

| Unknown today | How to resolve | Blocks |
|---|---|---|
| CSE format/timezone/labels | Obtain dataset, profile it, confirm uncertain interpretation | CSE parser and findings |
| Actual Composio account schemas/scopes | Export pinned schemas, complete OAuth and tool smoke tests | Account-specific tool arguments/capabilities |
| PR trigger configuration/payload/latency | `get_type`, create trigger, capture signed sample and measure | Claim of event-driven merge replay |
| Elastic provisioned version/features | Record version; run required queries/mappings | Live evaluation |
| OpenAI model access/credits | Structured/tool-call smoke test | Live agents |
| Slack workspace installation permission | Authorize and post test in selected channel | Slack workflow |
| Hosting plan/budget | Choose provisioned resources and validate always-on worker | Public hosted runtime |

These are explicit setup tests. None can be truthfully filled in by guessing. Everything under application control (contract names, IDs, paths, state transitions, isolation, recovery, and acceptance behavior) is specified above.

## 12. Gmail scope revision

Gmail notifications are now required build scope, optional for each user to enable. Add the ten Gmail acceptance cases in [document 08](08-GMAIL-NOTIFICATIONS.md) to the original 40-case matrix. P3 owns the adapter; P4 owns Settings/history; P1 merges the policy/delivery model and route registration. Budget an additional 3-5 person-hours plus account approval time. These tickets join checkpoint 3 for initial notifications and checkpoint 4 for verified outcomes.
