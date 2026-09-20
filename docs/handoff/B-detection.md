# Track B: baselines, detector, correlator

**Owner:** B. **Branch:** `track/b-detection`. **Milestones:** M2 baselines, M3 streaming detector, correlator, and the API.

You build the watchdog. It is the middle 40 seconds of the demo and the thing C spends all night attacking. It is also the longest single milestone of the night, so protect your time: signals first, polish never.

## Checklist

- [x] **20:15** `minny/api/app.py` router wiring confirmed; `routes_detect.py` serving real artifacts
- [x] **21:00** Consume A's `events.parquet`
- [x] **22:00** `baselines.json` built and merged (**C tests against it**)
- [x] **23:00** S1 through S8 firing; real incident lines produce alerts (**C3**)
- [x] **00:00** Correlator produces one incident naming david_m and sarah_j
- [ ] **01:00** Replay engine + SSE stream live, D consuming it (**C4**)
- [x] **02:00** Non-incident March alert count measured: **zero**
- [ ] **03:00** Rule hot-reload from `rules.yaml` for C's blue agent (**C5**)

## Hour zero, before the parquet exists

Do not sit idle until 21:00. Write every signal against the column contract in [00-CONTRACTS.md](00-CONTRACTS.md) section 1 and test it on a 20-row hand-written CSV you fake yourself. The signals are pure functions of `(event, baselines)`; they do not care where the rows came from. When A's parquet lands at C2 you should be swapping the data source, not starting to code.

Also ship `minny/api/app.py` at 20:15 with all four routers imported by the exact names in section 12, each import wrapped so a missing module logs a warning rather than killing the process. Three people are blocked on that file existing, and it must never need editing again.

## M2: baselines (target 22:00)

`minny/baselines/` writes `data/baselines.json` to the shape in [00-CONTRACTS.md](00-CONTRACTS.md) section 4.

**Fit on `ts < 2026-03-01` and nothing else.** March is held out. If one March event leaks into the fit, every number C reports in M5 is worthless and nobody will notice until the judges ask how we validated. Make the window a single constant, assert the max fitted timestamp is under it, and print the assert.

Per user: `ips` (expect exactly one each, and check that, because a user with two baseline IPs changes what S1 means), `allowed_paths` (at least one 200), `denied_paths` (at least one 403 and zero 200s), `templates_seen`, `hour_hist`, and the `auth_fail` gap distribution. Globally: `template_freq`, `param_keys` per template, `privileged_templates`, and the `ip_owner` reverse map.

Two things to get right:

- **`hour_hist` is for explanation text only.** It never triggers an alert. Legitimate off-hours access is all over this dataset, including sarah_j downloading the confidential zip at 00:19 on 6 March from her own IP. A signal that fires on her turns the demo into an argument about false positives instead of a story about David.
- **`privileged_templates`** is everything under `/api/admin/` plus any template seen fewer than *k* times globally that returns `200` to a `POST`. Pick *k*, record it in the file, and be able to say why on stage.

**Done when** it loads in under a second and answers "has user X ever succeeded on Y, used IP Z, or sent param P to template T" without a scan.

## M3: signals, correlator, replay (target 01:00, the core of the night)

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

S1 and S6 carry the demo. S6 is the one nobody else would have written and it is what makes the story a *mechanism* rather than a list of anomalies. Spend your time there.

Two traps:

- **Validate the S3 threshold against the baseline window before trusting it.** 3-in-30s must produce zero hits across Aug-Feb. If it does not, raise it and say so. C's `slow_guess` operator exists specifically to walk under whatever you pick, which is the point.
- **S4 must exclude normalized ID variation.** Templates already collapse post and avatar IDs; if you work on `base` instead of `template`, every forum view on a new post fires S4 and the stream becomes noise.

### Correlator

Union alerts into an incident when they share an entity (user, IP, IP owner, `obj_id`, or target file) inside a rolling 72-hour window. Output per section 6.

Role resolution: the **attacker** is the IP owner behind S1 alerts and the author of any S6 vector post per S7; the **victim** is the account whose session performed the privileged action or was logged into from the wrong IP. When the two disagree, prefer the S6 chain and drop `confidence` to `medium` rather than guessing confidently. C's `own_ip_takeover` operator is built to break exactly this inference, so handle a `null` `ip_owner` deliberately rather than by exception.

**Explanations are template-generated from signal values.** *"sarah_j logged in from 10.0.8.45, which belongs to david_m. She has used only 10.0.5.12 in 7 months."* An LLM may smooth the wording; it must never add a fact that is not in `value` or `evidence_lines`. If a judge asks where a sentence came from, the answer is a template and a field, not a model.

Set `evidence_emails` on the incident when D's `data/email_evidence.json` exists and a message links per section 11. It is a lookup on entity and time window, it is five lines, and it must be wrapped in a try/except that swallows everything. A missing or malformed mailbox file changes nothing about the incident. **No signal ever reads email.** Alerts stay reproducible from `events.parquet` alone, which is what makes M5's numbers mean anything.

### Replay engine

Reads events in `ts` order, merges C's injection queue by timestamp, and emits at a configurable speed (about one simulated hour per second for the demo) plus an "as fast as possible" mode for evaluation. The injection queue is the judge panel's whole mechanism: C pushes variant events in, they arrive in time order, the detector cannot tell them apart.

Then `GET /api/stream` as SSE per section 12: `event`, `alert`, `incident`, `replay_state`, `heartbeat` every 15s, monotonic `seq`. D is building against `fixtures/mock/stream.ndjson` all night, so the moment your frames match that file the UI lights up with no further work from either of you.

### Rule hot-reload

C's blue agent appends to `detection-rules/rules.yaml`. Load it at startup and re-read on change, evaluating rules with the same feature dictionary the built-in signals use. The DSL and the gate are C's; you provide evaluation and the alert emission. A rule that fails to parse is skipped with the error surfaced through `/api/blue/proposals`, never a crash.

## Done when

Replaying March produces **one** incident naming david_m as attacker and sarah_j as victim, with every alert's evidence lines matching A's case file, and you have **measured the number of non-incident alerts on March**: target zero or close to it, with each remaining one justified individually. "Close to zero" is not a number. Write the count down at 02:00 and hand it to C for `metrics.json`, because that figure is the credibility of the whole watchdog and A will say it on stage.


---

# Wave status: M2 and M3 are done

Rebuild everything with two commands, in this order:

```
python -m minny.baselines.build     # -> data/baselines.json
python -m minny.detect.run          # -> data/alerts.json, data/incidents.json
```

Both take `MINNY_DATA_DIR`. The second replays the baseline window as a
control *and* the held-out window, and prints both results together.

## The numbers

| Measurement | Value |
|---|---|
| Baseline fit | 157,818 events, max fitted ts `2026-02-28T21:59:11-05:00`, asserted below the cutoff |
| Users with exactly one baseline IP | 10 of 10 |
| Alerts across the 157,818-event baseline window | **0** |
| S3 hits in the baseline window at 3-in-30s | **0** |
| March alerts | 25: S1×14, S2×1, S3×2, S4×2, S5×3, S6×1, S8×2 |
| March incidents | **1**, `attacker=david_m (high)`, `victim=sarah_j (high)` |
| Non-incident March alerts | **0** |
| Alerts touching a line outside the known incident | **0** |
| Full 180,800-event replay | ~1.3 s; `baselines.json` loads in ~11 ms |

Every one of the 25 March alerts lands on a line listed in
[GROUND-TRUTH.md](GROUND-TRUTH.md), and `tests/test_signals.py` asserts that
as a set containment rather than a count, so a future signal that fires
somewhere else fails the suite rather than quietly inflating the total.

## Thresholds, and why each one

| Constant | Value | Justification |
|---|---|---|
| `RARE_POST_SUCCESS_K` | 100 | The rarest legitimate template in seven months appears 1,778 times. There is nothing to tune between 100 and 1,778. |
| `RARE_STATUS_N` (S8) | 10 | The rarest baseline status is 401 at 782. 400 and 500 have a baseline count of 0. |
| `AUTH_FAIL_THRESHOLD` / window (S3) | 3 in 30 s | No account ever produced **more than one** 401 in any 30-second window in the baseline. Two failures of headroom, zero baseline hits. |
| `PRIVILEGED_AFTER_VIEW_S` (S6) | 5 s | The real gap is 1 s. A person who read a post and then decided to call an admin endpoint does not do it in five seconds. |
| `AUTHORSHIP_WINDOW_S` (S7) | 10 s | The real gap is 3 s. Across all 180,800 lines this produces exactly **one** authorship link: post 1042 to david_m. |
| `CORRELATION_WINDOW` | 72 h | The chain spans 47.5 h from first failed login to second download. |

## Decisions the other tracks need

**`global.privileged_templates` is `[]`, and that is correct.** The baseline
window contains no `/api/admin/` traffic at all, so listing the endpoint would
mean reading it out of March, a leak in the detector's own favour, which is
worse than an empty list. The policy lives in `global.privileged_rule`
(`prefixes`, `rare_post_success_k`) and `Baselines.is_privileged(template,
method, status)` evaluates it at detection time. That rule also catches a
renamed endpoint: a POST returning 200 on a template the baseline has never
seen is privileged whatever it is called, which is what survives C's
`param_rename`-style mutations.

**Fields added to `baselines.json` since the contract froze**, all additive:
`users[u].denied_counts`, `.months_observed`, `.first_seen`, `.last_seen`,
`.auth_fail.max_in_30s`, and `global.status_freq`, `global.rare_status_n`,
`global.privileged_rule`, `global.auth_fail_window_s`. The explanation
templates quote these directly, which is how a sentence stays traceable to a
field.

**`GET /api/incidents/{id}`** returns the incident with `alerts` still the
contract's array of IDs, plus `alerts_expanded` carrying the full objects.

**An account with no baseline at all** gets one S1 alert at `medium` on its
first appearance and nothing after. Every other signal guards on an empty
profile, so without this a name that first appears in the held-out window
would produce no output whatever it did.

**`hour_hist` is recorded and never read by a signal.** There is no hour
threshold anywhere in `minny/detect/`.

## Still to build (later wave)

Replay engine, `GET /api/stream` SSE, `POST /api/replay/control`, and rule
hot-reload from `detection-rules/rules.yaml`. `minny/detect/events.py` already
exposes `merged()` for interleaving C's injection queue by timestamp, and
`Detector`/`Correlator` are both streaming-shaped (`feed()` and `add()` take
one item at a time), so the engine is a driver, not a rewrite.
