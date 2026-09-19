# Minny — technical scope and integration specification

Draft 2 · 19 September 2026 · Prepared for four parallel builders

> **This is the integration reference, not the current build plan.** The plan being built is [docs/handoff/README.md](../handoff/README.md), which is scoped to the actual deadline and says which parts of this package apply tonight (Composio tool slugs and webhooks, Elastic mapping, Gmail scopes, the shared JSON schemas) and which are out of scope (invite-only accounts, PostgreSQL, migrations, the durable job queue, the outbox, Render deployment). The four-person ownership table below is superseded by the A/B/C/D track split in the handoff.

This package specifies the remaining build from an unprovisioned starting point. It is a proposed implementation contract, not a claim that accounts, integrations, deployment, or live tests already exist. Product code has not been changed. Repository inspection: `Ch33zig/Minny`, `main`, commit `675ad48d76638f71e1ce35708f1f4294d269c6e5`, refreshed during this review.

## Read in this order

1. [Platform, identity, persistence, and shared contracts](01-PLATFORM-AND-CONTRACTS.md)
2. [Agents, OpenAI, Huawei, and synthetic telemetry](02-AGENTS-AND-SIMULATION.md)
3. [Elastic, CSE investigation, and detection correctness](03-ELASTIC-AND-CSE.md)
4. [Composio: developer setup, user onboarding, tools, triggers, and recovery](04-COMPOSIO.md)
5. [Frontend, Sentry, and user-visible behavior](05-FRONTEND-AND-SENTRY.md)
6. [Provisioning, four-person delivery order, and acceptance tests](06-SETUP-DELIVERY-AND-TESTS.md)
7. [Gmail notification integration](08-GMAIL-NOTIFICATIONS.md)
8. [Environment variable template](environment.example), [machine-readable contract examples](contract-examples.json), and [contract schema notes](07-CONTRACT-SCHEMAS.md)

All repository-relative paths in these documents are proposed implementation locations in Minny, unless identified as existing. Shell commands involving `backend.cli`, migrations, Docker Compose, or tests describe the required interface of code to be built; they do not run against today's repository. SDK snippets illustrate verified documentation surfaces but still require the selected dependency lock and live smoke tests.

## Decisions for this draft

| Concern | Decision | Why |
|---|---|---|
| Backend | Python 3.12, FastAPI, Pydantic 2, SQLAlchemy 2, psycopg 3, Alembic | One language for agents, data parsing, integrations, and API |
| State | PostgreSQL 16; durable jobs and outbox in Postgres | Survive restarts without adding Redis |
| Frontend | Preserve current vanilla JavaScript/HTML/CSS; separate ES modules | Avoid a framework rewrite |
| Browser build | Node 22, esbuild, `@sentry/browser`; exact dependencies locked at setup | Bundle Sentry and modules predictably |
| Runtime | One API process and one worker process | HTTP requests do not wait for agent runs |
| Hosting | Proposed Render web service + worker + Postgres; local Compose first | Concrete deployment topology; no resources purchased or created |
| Public origin | FastAPI serves built frontend and `/api/v1` from one origin | Avoid cross-site cookie/CORS problems |
| LLM | OpenAI Responses API; configurable `gpt-5-mini` starting model | Structured outputs and narrow application tools |
| Coordination | Application-owned supervisor and bounded specialist loops | Durable state and testable collaboration |
| Huawei | openJiuwen multi-agent challenge; framework optional under supplied rules | Demonstrate genuine feedback and tool use |
| Elastic | Elastic Cloud Hosted deployment; use raw Elasticsearch APIs | Explicit ECS mapping and ES|QL control |
| Composio | Managed OAuth, GitHub + Slack + Gmail, pinned direct tool execution | Precise actions, user-selected destinations, inspectable recovery |
| App access | Invite-only local accounts and opaque server sessions | Real user isolation without adding another identity vendor |
| Product scope | Workspace owners connect their own GitHub/Slack/Gmail; members may view/run internal tests | No accidental shared credential authority |
| Replay | Reuse the exact immutable event set; evaluate at explicit merged rule revision | Fair before/after comparison |

The existing `.openai/hosting.json` remains untouched. The Render topology is a proposed backend deployment design, not a deployment performed in this task. If you retain the current static-site hosting, add the cross-origin cookie/CORS work described in the platform document before using it with the API.

## What actually exists

| Existing asset | Reuse | Remaining work |
|---|---|---|
| `dist/index.html` | Layout and visual sections | Real settings, login, findings, evidence, workflow links |
| `dist/styles.css` | Visual language | Additional states, responsive settings, accessibility |
| `dist/app.js` | Visual behavior reference | Replace scripted detections, PR numbers, timers, coverage increments |
| `README.md` | Repository identity | Full setup and demo guide |
| `.openai/hosting.json` | Existing hosting metadata | Does not provision backend, database, secrets, or worker |

Everything else in this package must be built or provisioned. No existing API, database, Elastic index, OpenAI integration, Composio project, Sentry project, or CSE parser was found. The user confirmed none of those services is set up.

## Definition of a working product

1. A user logs into Minny, creates a workspace, connects GitHub and their chosen Slack/Gmail notification channels, and selects destinations.
2. Setup verifies access and installs the repository trigger; the UI reports each capability separately.
3. CSE logs are ingested with provenance. Findings state who/what/when/how and link to actual records.
4. A user selects a supported technique and starts an experiment.
5. OpenAI proposes a structured plan. Deterministic code creates consistent synthetic events. A critic can reject and request revisions.
6. Elastic evaluates the frozen event set against a versioned rule set. A complete miss produces an evasion; errors never do.
7. A gap issue and Slack thread are created through Composio. Blue requests evidence and rule evaluation, revising its proposal if validation fails.
8. A validated proposal becomes a GitHub PR through Composio. A human reviews and merges.
9. A signed Composio event wakes a durable job. Minny independently checks merge status, fetches the rule at the merged commit, validates it, and re-evaluates the saved event set.
10. Only successful detection updates coverage. Issue closure and enabled Slack/Gmail notifications follow, with separately visible delivery status.
11. One bounded follow-up variant can test the strengthened rule. It receives a new variant ID and cannot overwrite the prior result.

## Scope tiers

**Required core:** one supported technique family, two meaningful variants, one real CSE investigation, real Elastic evaluation, real OpenAI reasoning, genuine critic/Blue feedback, real Composio issue/PR/merge replay, user connections, tracing plus replay, restart recovery, four ownership boundaries, and user-configurable Gmail notifications.

**After core works:** second technique, per-PR review feedback to Blue, notification preferences, more fixtures, additional CSE detection rules, opt-in bounded continuous testing.

**Explicitly outside this MVP:** malware execution; production endpoint access; enterprise SSO; billing; arbitrary third-party tools; Kubernetes; broad ATT&CK coverage claims; automatic GitHub merge; copying real customer logs into public issues; Jira/Notion integrations; OMNI multimodal Huawei track; claiming scheduled Elastic Security alerts when only ES|QL tests exist.

## Four-person ownership

| Owner | Track | Exclusive code ownership | Integration obligation |
|---|---|---|---|
| P1 | OpenAI + Huawei | `backend/core/`, `backend/agents/`, `backend/simulation/`, `backend/api/`, `contracts/`, root Python dependencies/migrations | Identity, schema contracts, state machine, agent tools, queue, API |
| P2 | Elastic + CSE | `backend/detection/`, `backend/data/`, `detection-rules/`, `fixtures/`, `scripts/elastic/` | Versioned evaluation and provenance-backed findings |
| P3 | Composio | `backend/workflows/`, `scripts/composio/`, `contracts/vendor/composio/`, workflow tests | Connections, resource selection, action lifecycle, verified merge envelope |
| P4 | Sentry + product | `frontend/`, existing `dist/`, `backend/observability/`, browser tests, `infra/`, root Node dependencies | Dashboard, tracing/replay, deployment configuration |

P1 alone edits `backend/main.py`, database migration files, and shared models. P2/P3/P4 supply their adapters and migration requirements through defined interfaces. P4 alone edits Docker/build configuration, while P1 specifies module entry points. P3 may update only its vendor-schema subtree within `contracts/`. Each person owns tests for their module. Cross-owner changes require a small request to the file owner, not simultaneous edits.

## What cannot honestly be fixed in advance

The CSE data layout and labels have not been provided. Their field mapping and findings must come from inspection; examples in this package are not findings. Service-generated account IDs, URLs, keys, actual OAuth grants, available toolkit schemas, provisioned Elastic version, and latency must be captured during setup. Each such dependency has a concrete verification gate in document 06. Failed gates block only the affected capability and appear explicitly in the UI.

The sponsor criteria are taken from the user's pasted track descriptions. Vendor implementation references are linked beside the relevant requirements. No prize eligibility or end-to-end functionality has been verified with sponsor accounts.
