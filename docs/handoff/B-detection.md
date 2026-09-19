# Track B — baselines, detector, correlator

**Owner:** B. **Branch:** `track/b-detection`. **Milestones:** M2 baselines, M3 streaming detector, correlator, and the API.

You build the watchdog. It is the middle 40 seconds of the demo and the thing C spends all night attacking. It is also the longest single milestone of the night, so protect your time: signals first, polish never.

## Checklist

- [ ] **20:15** `minny/api/app.py` router wiring confirmed; `routes_detect.py` stub returning fixtures
- [ ] **21:00** Consume A's `events.parquet`
- [ ] **22:00** `baselines.json` built and merged — **C tests against it**
- [ ] **23:00** S1 through S6 firing; real incident lines produce alerts — **C3**
- [ ] **00:00** Correlator produces one incident naming david_m and sarah_j
- [ ] **01:00** Replay engine + SSE stream live, D consuming it — **C4**
- [ ] **02:00** Non-incident March alert count measured and justified line by line
- [ ] **03:00** Rule hot-reload from `rules.yaml` for C's blue agent — **C5**

## Hour zero, before the parquet exists

Do not sit idle until 21:00. Write every signal against the column contract in [00-CONTRACTS.md](00-CONTRACTS.md) section 1 and test it on a 20-row hand-written CSV you fake yourself. The signals are pure functions of `(event, baselines)`; they do not care where the rows came from. When A's parquet lands at C2 you should be swapping the data source, not starting to code.

Also ship `minny/api/app.py` at 20:15 with all four routers imported by the exact names in section 12, each import wrapped so a missing module logs a warning rather than killing the process. Three people are blocked on that file existing, and it must never need editing again.

## M2 — baselines (target 22:00)

`minny/baselines/` writes `data/baselines.json` to the shape in [00-CONTRACTS.md](00-CONTRACTS.md) section 4.

**Fit on `ts < 2026-03-01` and nothing else.** March is held out. If one March event leaks into the fit, every number C reports in M5 is worthless and nobody will notice until the judges ask how we validated. Make the window a single constant, assert the max fitted timestamp is under it, and print the assert.

Per user: `ips` (expect exactly one each, and check that — a user with two baseline IPs changes what S1 means), `allowed_paths` (at least one 200), `denied_paths` (at least one 403 and zero 200s), `templates_seen`, `hour_hist`, and the `auth_fail` gap distribution. Globally: `template_freq`, `param_keys` per template, `privileged_templates`, and the `ip_owner` reverse map.

Two things to get right:

- **`hour_hist` is for explanation text only.** It never triggers an alert. Legitimate off-hours access is all over this dataset, including sarah_j downloading the confidential zip at 00:19 on 6 March from her own IP. A signal that fires on her turns the demo into an argument about false positives instead of a story about David.
- **`privileged_templates`** is everything under `/api/admin/` plus any template seen fewer than *k* times globally that returns `200` to a `POST`. Pick *k*, record it in the file, and be able to say why on stage.

**Done when** it loads in under a second and answers "has user X ever succeeded on Y, used IP Z, or sent param P to template T" without a scan.

## M3 — signals, correlator, replay (target 01:00, the core of the night)

### Signals

Each emits `{name, value, severity, evidence_line}` and becomes an alert per [00-CONTRACTS.md](00-CONTRACTS.md) section 5.

| ID | Name | Fires when | Severity |
|---|---|---|---|
| S1 | `ip_mismatch` | `ip` not in `ips[user]` | high if the IP belongs to another user; capture `ip_owner` in the alert |
| S2 | `first_success_on_denied` | status 200 on a template in `denied_paths[user]` | high |
| S3 | `auth_fail_burst` | 3+ 401s for the same `(user, ip)` within 30s | medium; high when combined with S1 |
| S4 | `novel_template` | template never seen by this user | high when globally unseen in the baseline |
| S5 | `unexpected_params` | query keys not in `param_keys[template]` | medium |
| S6 | `content_triggered_privileged_action` | request to a privileged template by user U within 5s of U viewing `forum/view/{id}` | high; record `obj_id` as the suspected vector |
| S7 | `post_authorship` | A gets 302 on `forum/new` and views `forum/view/{id}` within 10s | **supporting only, emits no alert** |

S1 and S6 carry the demo. S6 is the one nobody else would have written and it is what makes the story a *mechanism* rather than a list of anomalies — spend your time there.

Two traps:

- **Validate the S3 threshold against the baseline window before trusting it.** 3-in-30s must produce zero hits across Aug–Feb. If it does not, raise it and say so. C's `slow_guess` operator exists specifically to walk under whatever you pick, which is the point.
- **S4 must exclude normalized ID variation.** Templates already collapse post and avatar IDs; if you work on `base` instead of `template`, every forum view on a new post fires S4 and the stream becomes noise.

### Correlator

Union alerts into an incident when they share an entity — user, IP, IP owner, `obj_id`, or target file — inside a rolling 72-hour window. Output per section 6.

Role resolution: the **attacker** is the IP owner behind S1 alerts and the author of any S6 vector post per S7; the **victim** is the account whose session performed the privileged action or was logged into from the wrong IP. When the two disagree, prefer the S6 chain and drop `confidence` to `medium` rather than guessing confidently. C's `own_ip_takeover` operator is built to break exactly this inference, so handle a `null` `ip_owner` deliberately rather than by exception.

**Explanations are template-generated from signal values.** *"sarah_j logged in from 10.0.8.45, which belongs to david_m. She has used only 10.0.5.12 in 7 months."* An LLM may smooth the wording; it must never add a fact that is not in `value` or `evidence_lines`. If a judge asks where a sentence came from, the answer is a template and a field, not a model.

Set `evidence_emails` on the incident when D's `data/email_evidence.json` exists and a message links per section 11. It is a lookup on entity and time window, it is five lines, and it must be wrapped in a try/except that swallows everything — a missing or malformed mailbox file changes nothing about the incident. **No signal ever reads email.** Alerts stay reproducible from `events.parquet` alone, which is what makes M5's numbers mean anything.

### Replay engine

Reads events in `ts` order, merges C's injection queue by timestamp, and emits at a configurable speed (about one simulated hour per second for the demo) plus an "as fast as possible" mode for evaluation. The injection queue is the judge panel's whole mechanism: C pushes variant events in, they arrive in time order, the detector cannot tell them apart.

Then `GET /api/stream` as SSE per section 12: `event`, `alert`, `incident`, `replay_state`, `heartbeat` every 15s, monotonic `seq`. D is building against `fixtures/mock/stream.ndjson` all night, so the moment your frames match that file the UI lights up with no further work from either of you.

### Rule hot-reload

C's blue agent appends to `detection-rules/rules.yaml`. Load it at startup and re-read on change, evaluating rules with the same feature dictionary the built-in signals use. The DSL and the gate are C's; you provide evaluation and the alert emission. A rule that fails to parse is skipped with the error surfaced through `/api/blue/proposals`, never a crash.

## Done when

Replaying March produces **one** incident naming david_m as attacker and sarah_j as victim, with every alert's evidence lines matching A's case file, and you have **measured the number of non-incident alerts on March** — target zero or close to it, with each remaining one justified individually. "Close to zero" is not a number. Write the count down at 02:00 and hand it to C for `metrics.json`, because that figure is the credibility of the whole watchdog and A will say it on stage.
