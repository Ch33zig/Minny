# Draft verification record

Verified 19 September 2026. This records document/contract checks only, not live integration acceptance.

- Refreshed repository main: `675ad48d76638f71e1ce35708f1f4294d269c6e5`; no product files modified.
- Four JSON Schemas checked against Draft 2020-12 with `jsonschema` 4.26.0.
- Four positive example fixtures passed, including UUID format checks.
- Four invalid evaluation fixtures were rejected: incomplete ingestion, incomplete query, detection without attack matches, and error without an error object.
- A rule using a ground-truth metadata field was rejected.
- Internal document links, fenced code blocks, and unresolved TODO/TBD markers checked.
- Selected GitHub tool and trigger slugs checked against downloaded official catalog content; account-specific argument schemas still require project-side export and smoke tests.
- Official documentation reviewed for Composio authentication, tool execution/versioning, scopes, connected accounts, triggers/webhooks; OpenAI model, structured outputs and function calling; Elastic ES|QL, refresh and API keys; Sentry Replay, browser tracing and FastAPI; Render web/worker deployment; GitHub and Slack scopes; JiuwenSwarm.

Not performed: account provisioning, credential tests, actual CSE inspection, product implementation, deployment, provider calls using team credentials, OAuth connection tests, webhook signature tests against a live project, end-to-end replay, or Sentry ingestion checks. These remain explicit acceptance gates in document 06.

The schemas do not prove semantic correctness, tenancy isolation, or detection quality. Those require the listed application and live tests.

## Gmail scope revision

Added Gmail through Composio as required build scope with per-user opt-in. Reviewed the official Composio Gmail catalog, Google Gmail scopes, and sending guide. Updated platform policy/delivery contracts, frontend requirements, environment inventory, provisioning tickets, and acceptance cases G01–G10. Rechecked local links, fenced blocks, JSON parsing, and archive integrity. No email was sent and no account was connected.
