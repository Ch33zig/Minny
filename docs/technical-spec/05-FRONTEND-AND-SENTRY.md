# Frontend, Sentry, and observable product behavior

Owner: P4. Preserve the current dashboard layout; replace simulated data and timer-driven success.

## 1. Frontend source/build layout

Move maintained source to `frontend/` and generate the existing `dist/` deployable directory. P4 performs the move once so no other builder edits generated files. Use ES modules and a small esbuild script; no React migration is required.

```text
frontend/
  index.html
  styles.css
  app.js                   # initialization and routing
  api.js                   # cookie/CSRF/idempotency/error handling
  state.js                 # last server sequence and selected resources
  observability.js         # Sentry init and scrubbing
  views/login.js
  views/integrations.js
  views/dashboard.js
  views/investigation.js
  components/coverage.js
  components/timeline.js
  components/evidence.js
  components/workflow.js
scripts/build-frontend.mjs
```

`npm run build` copies HTML/CSS and emits bundled `dist/app.js`. `npm test` runs browser/component tests. `npm run test:e2e` runs Playwright. Commit package lock; use `npm ci` in builds. Import `@sentry/browser` through the bundle. Secrets must never use a browser-build environment prefix. Public DSN/environment/release may be served by an allowlisted `/api/v1/public-config` response; add that route to the shared contract.

## 2. Views and user journeys

### Login and workspace

Invitation onboarding, login, logout, current workspace switcher. Show expired-session feedback with a return path to the current experiment. Do not cache sensitive API responses in local storage or a service worker. Changing workspace aborts pending requests and clears the previous workspace's state.

### Settings → Integrations

GitHub, Slack, and Gmail cards show actual provider identity, last checked time, connection status, reconnect/disconnect controls, and specific permission errors. Include repository/channel picker, base branch and rule prefix, trigger readiness, test actions, and automation policy. Connecting an account and selecting a destination are visibly separate steps.

Example user copy: “Connect GitHub to create detection issues and proposed rule changes in a repository you choose. You review and merge changes in GitHub.” Show Slack message destination before saving. Do not expose Composio's project API key or require users to paste provider tokens into Minny.

Setup status derives from backend capabilities. GitHub unavailable permits simulation-only evaluation but disables external publication. Slack unavailable permits GitHub workflow with a visible notification warning. A complete sponsor demo must pass both integrations and merge replay.

### Dashboard

Select only supported techniques/personas. Button is “Run experiment”; while running, show stage, elapsed time, stop action, and last update timestamp. Display actual run ID, frozen variant ID, rule revision, and provenance.

Coverage: gray untested, blue testing, red unresolved gap, amber remediating/stale, green detected in tested variants. Use icons/text, not color alone. The coverage summary reads “X of Y tested technique paths detected,” with tooltip explaining limits. Remove fabricated “4,981 normal events,” PR #184, and unconditional success timers.

### Experiment detail

Show: attacker hypothesis, validated plan summary, compiler validation, telemetry rows, baseline query and result, concise agent messages, Blue proposal/tests, issue/PR/Slack URLs, merge state, loaded commit SHA, replay evidence. Historical miss stays visible beside later remediation. A failed provider call displays error stage and retryability; it never changes to EVADED.

Use DOM text nodes/`textContent` for log fields and agent summaries. Treat model output, GitHub text, and log data as untrusted. If rendering Markdown, sanitize it and disable raw HTML. Validate external URL scheme/host from provider-normalized records, open links with `rel="noopener noreferrer"`.

### CSE investigation

Dataset/source, imported/quarantined counts, timestamp assumptions, timeline, entities, finding narrative, evidence record references, confidence, and alternative explanations. Separate observed facts from model hypotheses. Link each claim to source rows. Mark paced playback as “dataset replay.” No CSE result is prefilled before analysis.

## 3. API/polling behavior

Use `fetch` with same-origin credentials, CSRF header for mutations, and retained idempotency key per logical action. Abort on navigation/workspace change. Do not automatically retry non-idempotent requests with a new key.

During an active experiment poll incremental events every 1 second, using `after_seq`. On transient network failure back off to 2/4/8 seconds, maximum 15; show “Connection interrupted—last updated …”. Pause/slow polling in hidden tabs to 10 seconds. Refetch authoritative detail after reconnect. Deduplicate by sequence; reject older versions. Poll waiting-for-merge state every 5 seconds. Stop polling terminal experiment-only views unless a remediation remains active.

Render stage transitions as received. Animations may visualize persisted progress but cannot invent a provider result. On a second click before response arrives, reuse the original idempotency key and disable duplicate submit.

Frontend uses opaque `technique_id` and `variant_id`, replacing the current array-index matrix association. Coverage is wholly server-derived. Refreshing the page or reopening a saved URL must reconstruct the experiment accurately.

## 4. Sentry setup

Create one Sentry organization and projects `minny-web` (Browser JavaScript) and `minny-backend` (Python/FastAPI). Worker uses the backend project with `service=worker`; API uses `service=api`. Set environment `development` or `demo`, release equal to the Git commit SHA. DSNs are ingestion identifiers; a Sentry auth token for source-map upload remains a build secret.

Choose **Tracing and Session Replay** as the two products beyond error monitoring. Do not claim an SDK install alone fulfills the supplied track criteria. Capture and fix a real observed problem, preserving trace/replay links and before/after evidence.

### Browser configuration

```javascript
import * as Sentry from "@sentry/browser";

Sentry.init({
  dsn: publicConfig.sentry_web_dsn,
  environment: publicConfig.environment,
  release: publicConfig.release,
  integrations: [
    Sentry.browserTracingIntegration(),
    Sentry.replayIntegration({maskAllText: true, blockAllMedia: true}),
  ],
  tracesSampleRate: 1.0,
  replaysSessionSampleRate: 1.0,
  replaysOnErrorSampleRate: 1.0,
  tracePropagationTargets: [/^\/api\/v1\//],
  sendDefaultPii: false,
  beforeSend: scrubErrorEvent,
});
```

Use 100% sample rates only for the small controlled demo/testing environment; lower them deliberately for broader use. `scrubErrorEvent` removes credentials, callback nonces/URLs, request bodies, source log text, and provider tokens. Block login/settings secrets and sensitive evidence containers from replay; masking text is not a substitute for checking captured network/breadcrumb data. Replay captures the interaction sequence; it need not expose raw logs. [Replay setup](https://docs.sentry.io/platforms/javascript/session-replay/).

Browser tracing is enabled with `browserTracingIntegration`; restrict propagation to Minny endpoints. If using absolute API URLs, add an exact escaped origin/path matcher and configure matching backend CORS headers. Verify fetch spans and matching backend trace IDs in Sentry. [Browser tracing](https://docs.sentry.io/platforms/javascript/tracing/).

### Backend and worker

Initialize Sentry before importing/creating the application:

```python
import sentry_sdk

sentry_sdk.init(
    dsn=settings.sentry_backend_dsn,
    environment=settings.app_env,
    release=settings.release,
    traces_sample_rate=1.0,
    send_default_pii=False,
    before_send=scrub_error_event,
)
```

FastAPI integration supplies request instrumentation; add explicit application-stage spans and worker transaction boundaries. Test the selected SDK's queue trace propagation instead of assuming a new process inherits context. Persist a validated minimal tracing carrier with the job and use SDK continuation APIs; otherwise link traces through experiment/job IDs and explicitly label the gap. [FastAPI integration](https://docs.sentry.io/platforms/python/integrations/fastapi/).

P4 implements `backend/observability/init.py`, `spans.py`, and `scrub.py`. P1/P2/P3 add the helper calls in their own modules. Scrub errors and transaction/span payloads separately; error-event scrubbing does not automatically sanitize all telemetry products. Disable automatic LLM prompt/completion capture unless redaction has been verified.

Required span names: `experiment.plan`, `telemetry.compile`, `telemetry.validate`, `elastic.bulk_ingest`, `elastic.evaluate`, `blue.propose`, `rule.validate`, `composio.issue.create`, `composio.pr.create`, `webhook.verify`, `rule.load_merged`, `replay.evaluate`. Context attributes: experiment_id, variant_id, job_id, stage, provider request ID, release, rule hash, event count. Avoid unbounded metric labels and raw payloads.

### Evidence of actual improvement

Save `docs/sentry-evidence.md` with observed problem, trace/replay URL, relevant span/timing or UI sequence, fix commit, repeat measurement, and limitations. Suitable examples if they actually occur: blocking provider SDK call delaying HTTP response, repeated per-event ingestion instead of bulk, or a reconnect callback leaving Settings stuck. Fault-injection tests may show resilience but must be labeled tests, not invented production incidents.

## 5. Required checks

- Page refresh during experiment shows persisted state, not a restarted scripted demo.
- Two runs of the same technique do not inflate coverage.
- Different workspace data never flashes after switching.
- Untrusted telemetry HTML renders as text.
- Missing GitHub connection displays simulation-only mode; failed Elastic query displays error.
- PR closed without merge never animates green.
- Replay success is shown before/independently from notification delivery.
- A real browser session appears in Replay; a fetch trace reaches backend; worker trace is linked.
- Login password, OAuth link/nonce, raw CSE evidence, and API secrets are absent from sampled Sentry data.
- Keyboard navigation, visible focus, labels, empty states, and narrow-screen layout work.

Source-map upload is optional for the first demo but should be configured if minification makes errors unreadable. Its token stays in CI/build secrets. Missing source maps do not justify exposing server keys or embedding tokens in public JavaScript.

## 7. Gmail settings and delivery UI

Implement the [Gmail addendum](08-GMAIL-NOTIFICATIONS.md): sender connection, recipient list, event toggles, explicit enable/save, test email, per-recipient status, reconnect, and uncertain-send retry acknowledgement. Keep email addresses and bodies out of Replay/breadcrumbs. Label successful API submission “Sent via Gmail,” not “Delivered” or “Read.” Gmail failure cannot roll back remediation. P4 owns this UI; P3 owns sending and delivery state.
