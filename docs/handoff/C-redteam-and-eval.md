# Track C: red team, evaluation, blue agent

**Owner:** C. **Branch:** `track/c-redteam`. **Milestones:** M4 generator, M5 eval harness, M6 blue agent.

You are the reason this project is not a demo of a thing we already knew. Anyone can catch David when they were told about David. You break the detector hundreds of ways and produce the numbers that say whether it survived.

Your track is the most over-budget of the four: roughly 12 hours of estimate in a 9.5-hour window. **M5 is never cut. M6 is the first thing to go** if you are behind at 02:30, and the plan already says so, so cutting it is following the plan rather than failing at it.

## Checklist

- [ ] **20:15** Renderer and critic written against the CLF format, no parquet needed
- [ ] **21:00** Consume A's `size_table.json` and `access_matrix.json`
- [ ] **22:00** First variants rendering, critic rejecting bad ones
- [ ] **23:00** 20+ critic-accepted variants merged (**C3**)
- [ ] **00:30** ~200 variants, LLM parameter generation working, blind test passed
- [x] **02:30** `python eval.py --seed 42` writes `metrics.json` (**C5, this is the one that cannot slip**)
- [x] **03:00** Judge panel endpoint live for D
- [ ] **04:30** Blue agent with one real before/after, or cut cleanly
- [ ] **05:00** Everything precomputed and seeded for the demo

## Hour zero, before anything from A or B

The renderer does not need a parquet file. It needs the log format, which you already have. Build `minny/redteam/render.py` and `critic.py` at 19:30 against the format spec, using placeholder sizes, then swap in A's real `size_table.json` at C2. By 21:00 you should be generating, not starting.

## M4: the generator (target 00:30)

### Families

Derived from the real incident, fixed IDs per [00-CONTRACTS.md](00-CONTRACTS.md) section 8:

- **F1 `credential_takeover`**: failed logins as the victim, then a success, then access.
- **F2 `content_privilege_escalation`**: malicious post, victim views it, privileged action, attacker's first success on a denied file.
- **F3 `cover_download`**: victim's account used from the attacker's IP to pull the asset.
- **F4 `full_chain`**: F1 + F2 + F3, the real thing.

### Mutation operators

Each one targets a specific signal. That is the point: a variant that evades tells you *which* assumption was load-bearing.

| Operator | What it does | Targets |
|---|---|---|
| `slow_guess` | failed logins 30 to 120 minutes apart | S3's 30-second window |
| `own_ip_takeover` | login as victim from a third, previously unseen IP | S1's `ip_owner` evidence and the correlator's attacker inference |
| `param_rename` | innocuous-looking query keys, or none | S5 |
| `victim_swap` | a different authorized user as victim | attribution |
| `target_swap` | a different sensitive file, real size, real authorized users | asset-specific tuning |
| `business_hours` | shift everything into 09:00-17:00 on a weekday | any hour-based heuristic |
| `delay_gap` | widen view-to-action or escalation-to-exfil | S6's 5-second window |
| `no_cleanup`, `no_cover_download` | drop steps | signals that assume the full chain |

`victim_swap` and `target_swap` must read A's `access_matrix.json`. Only sarah_j and nicole_h can touch the Q1 zip; a variant whose victim was never authorized is incoherent and the critic must reject it.

### The LLM's job, and its limits

Given a family and a persona (impatient insider, careful insider, outsider with stolen credentials), the model returns **JSON parameters only**: attacker, victim, target, operator list, timing offsets. Enum values are restricted to the dataset's real users, IPs, templates, and files.

**The LLM never writes a log line.** It never sees or emits an exploit. Attack forum posts exist in our output only as the log lines they would produce. Deterministic code renders everything, which is what keeps the output safe to publish and makes the whole harness reproducible from a seed.

The structured-output shape in [attack-plan.schema.json](../technical-spec/attack-plan.schema.json) is a reasonable starting point; note the warning in [07-CONTRACT-SCHEMAS.md](../technical-spec/07-CONTRACT-SCHEMAS.md) about deriving an all-required, nullable model-facing variant rather than passing the generic schema to a strict API.

### Renderer

Build CLF lines from **real benign lines used as templates**, overwriting only `ip`, `user`, `ts`, `path`, `status`, and `size`. Sizes come from A's `size_table.json`; a `(base, status)` pair listed under `variable_size_paths` must sample a real observed size rather than inventing one. Injected line IDs start above 180800 so a synthetic event can never collide with a real one. Inject into March at a seeded random start time.

### Critic: deterministic, rejects on failure

Not an LLM. Six checks:

1. Every line parses under A's regex.
2. Timestamps strictly increase within the variant.
3. Every status/size pair exists in the real table.
4. A `200` on a sensitive file happens only after an escalation step, or for an already-authorized user.
5. The victim is authorized for the privileged action used.
6. The declared operators are actually present in the rendered output.

Check 6 is the one people skip and it is the one that matters: if `slow_guess` is declared but the rendered gaps are 20 seconds, your per-operator table is fiction and you will report it on stage.

**Done when** ~200 labeled variants generate in a few minutes and **a teammate cannot pick the synthetic lines out of a blind mixed sample of 50.** Actually run that test with A or D at 00:30. It takes four minutes and it is the difference between "we generated attacks" and "we generated attacks that pass inspection."

## M5: evaluation harness (target 02:30, never cut)

This is the milestone that makes the project honest. Everything A says on stage comes out of it.

- **Benign stream:** March events minus the labeled incident lines. The incident is excluded when measuring false positives, or we would be counting our own success as noise.
- **Detection:** a variant counts as detected when an incident contains at least one of its `injected_lines`. Report overall, per operator, and per family. **The per-operator table is the most interesting artifact of the night**: it says precisely which evasions work.
- **Attribution:** of detected variants, the fraction where the incident names the correct attacker *and* victim. Detecting something and blaming the wrong person is not a win, and reporting the two separately is what a security team would actually ask for.
- **False positives:** alerts and incidents on the benign stream, per day. Get this from B at 02:00 and cross-check it yourself.
- **Time to detect:** log-time from `first_malicious_ts` to the first alert, plus wall-clock processing latency per event. Keep them separate; they answer different questions.
- **Real incident:** detected yes/no, attribution correct yes/no.

One command: `python eval.py --seed 42` writes `metrics.json` per section 9 plus the per-operator table.

**Done when** the numbers said on stage are reproducible from that command. Run it in front of A at least once, because A has to defend the numbers and will ask you what "detected" means.

## M6: blue agent (target 04:30, first to cut)

The rule DSL and gate are in [00-CONTRACTS.md](00-CONTRACTS.md) section 10. Parse with a small grammar. **No free-form code execution, ever, least of all from an LLM.**

Input to the agent: one evaded operator family with its variants and the features they produced, a sample of benign March features, and the DSL spec. Output: a proposed rule.

**The gate is the whole idea.** All three must pass:

1. Catches at least N% of a **held-out** set of variants from the same operator, generated with **different seeds and personas** than the ones the agent saw.
2. Adds no more than the FP budget on benign March.
3. Fires zero times on the baseline window, Aug through Feb.

Accepted rules append to `detection-rules/rules.yaml` and B's detector hot-reloads. Rejected rules are logged with the reason and shown in the UI: **the rejections are as much a demo asset as the acceptances**, because they prove the gate is real and not a rubber stamp.

**Build the planned rejection deliberately:** a rule whose predicate is essentially `query contains "csrf"` catches the original incident perfectly and fails gate 1 against `param_rename` variants. It is a 30-second story that shows exactly why overfitting to one incident is the failure mode this whole part of the project exists to prevent. Have it ready as a fixture even if the live agent is struggling.

**Done when** you have one real before/after: an operator that evaded, an accepted rule, and improved held-out detection with FP unchanged. One is enough. Two is not twice as convincing.

## Judge panel endpoint

`POST /api/redteam/generate` in `minny/api/routes_redteam.py`: takes `{attacker, victim, target, operators[], persona}`, generates a variant, injects it into B's live replay queue, and returns the variant label. D calls it, the incident appears on screen in seconds.

**Cache LLM responses for the common combinations before 05:00, with a live call as the fallback.** A judge will click it during a three-minute demo on conference wifi. Do not let a cold API call be the thing that ends the run.

---

## M4 as built

`python -m minny.redteam.generate --seed 42 --count 200`: 2 seconds, no API key, writes `data/variants.json` (200 accepted, 0 rejected, 1,810 lines, IDs 180801-182610, spanning 2-30 March) and `data/variants_rejected.json`.

Module layout, in the order the pipeline runs:

| Module | Does |
|---|---|
| `catalog.py` | Users, IPs, forum post IDs, topics, targets and the pool of real lines to clone, all read from `events.parquet` and `access_matrix.json` |
| `plan.py` | Parameters for one variant. Seeded by default; `--planner auto` uses Claude when `ANTHROPIC_API_KEY` is set, for parameters only |
| `families.py` | A plan becomes an ordered list of steps, each with a gap rather than a timestamp |
| `render.py` | Steps become log lines: size from `size_table.json`, skeleton cloned from a real line |
| `operators.py` | The nine evasions, and a verifier per operator that reads the rendered lines back |
| `critic.py` | Six checks; the first failure is the reported one |
| `generate.py` | The CLI, plus `--blind-check` |

Three decisions worth knowing about downstream.

**Declared operators are derived from the finished plan, not from what was requested.** Asking for `target_swap` and landing on the canonical target used to produce a label the lines did not support. `--declare-requested` turns the reconciliation off and runs the generator deliberately faulty: at seed 42 that yields 180 rejections out of 380 attempts, every one of them `operators_present`, which is the check doing exactly the job it exists for.

**The log is `-0400` everywhere.** All 180,800 real lines carry it, including August and December ones, so the DST split the brief predicted does not exist in the data and the renderer uses a constant offset. `events.parquet` stores `ts` in `America/New_York`, which for any date before 8 March renders an hour earlier than the text of the same line. That is worth knowing before quoting a `ts` column value next to a raw evidence line.

**Blind realism check, run twice at 40 real March lines against 10 synthetic.** First pass: 7 of 10 picked, and two of them only because `own_ip_takeover` was using 10.0.10.x and 10.0.12.x, subnets that appear nowhere in the corpus. That is a rendering tell rather than an attack signal, so the unseen-host pool moved onto the real 10.0.5-10.0.9 subnets with host octets that never occur. Second pass, fresh seed: 8 of 10 picked, every one of them by attack semantics: a user on someone else's host, a 200 on a file that account is denied, or the literal `script=success` payload string. Nothing was pickable by size, timestamp spelling, path shape or byte layout, and the two lines carrying no attack signal (a forum view, a logout) were indistinguishable. Synthetic sizes match the real distributions: `/dashboard` 2051.2 ± 26.8 against 2049.5 ± 29.0, forum views 2949 ± 602 against 3000 ± 577.

**Reproducibility was broken and is now pinned.** The operator draw iterated a set of strings while consuming the rng, and Python salts string hashing per process, so `--seed 42` produced a different batch in every interpreter while looking perfectly stable inside one. `test_generation_is_reproducible_across_processes` runs the generator under three `PYTHONHASHSEED` values and compares digests.

## M5 as built

`python eval.py --seed 42`: 30 seconds, no API key, writes `data/metrics.json` to contract section 9 and prints the tables below. 202 replays of the held-out window, 4,638,948 events through the detector.

| Module | Does |
|---|---|
| `minny/eval/stream.py` | The three streams: benign March (22,956 events, the 26 labeled incident lines removed), March intact, and one variant read back through `minny.parser` |
| `minny/eval/harness.py` | Feeds a stream through a fresh `Detector` and `Correlator` and scores one variant against the result |
| `minny/eval/metrics.py` | Outcomes to the section 9 file, plus the signal breakdown |
| `minny/eval/report.py` | The stdout tables, read back out of the built metrics rather than recomputed |
| `eval.py` | The command |

**Every variant is replayed alone.** 200 variants in one stream would share the correlator's 72-hour window, and two naming the same victim would collapse into one incident and each be scored as detected on the other's evidence. Nothing is batched: 200 full replays of the benign stream cost about 20 seconds, which is cheaper than a number that needs a caveat.

### The numbers, at seed 42

| | |
|---|---|
| Detection | **100%**, 200 of 200, and 100% in all nine operator rows |
| False positives | **0 alerts, 0 incidents** over 31 days of benign March |
| Attribution, of the 200 detected | attacker **53.0%** (106), victim **86.0%** (172), both **53.0%**, and **0 misattributions** |
| Time to detect, log time | median **0s**, p90 **52.6m**, max **5.4h** |
| Wall clock | **0.002 ms per event** |
| Real incident | detected, `inc_e30fc0`, david_m and sarah_j both correct, 25 alerts citing 22 of the 26 labeled lines |

### Why 100% is a result about the signals, not about the operators

Nine rows at the same rate say nothing on their own, so the harness also records which signals fired on each variant's own lines.

| Signal | Fired on | Only signal to fire | Detection without it |
|---|---|---|---|
| S1 `ip_mismatch` | 150 | **73** | **63.5%** |
| S2 `first_success_on_denied` | 100 | 0 | 100% |
| S4 `novel_template` | 100 | 0 | 100% |
| S5 `unexpected_params` | 67 | 0 | 100% |
| S3 `auth_fail_burst` | 54 | 0 | 100% |
| S6 `content_triggered_privileged_action` | 51 | 0 | 100% |
| S8 `anomalous_status` | 47 | 0 | 100% |
| S7 `post_authorship` | 0 | 0 | 100% |

S1 is the whole margin. Remove any other single signal and detection does not move, because every family ends in an act the overlapping signals also see. S7 firing on nothing is correct: it supports the correlator and never raises an alert.

### What each evasion actually switched off

Compared against variants of the same families without that operator, which matters because the operators are not drawn uniformly. These are the rows the blue agent is pointed at.

| Operator | Signal | With | Control | Suppressed |
|---|---|---|---|---|
| `delay_gap` | S6 | 0/91 | 51/109 | **100%** |
| `slow_guess` | S3 | 0/46 | 54/54 | **100%** |
| `param_rename` | S5 | 17/50 | 50/50 | 66% |
| `delay_gap` | S8 | 11/91 | 36/109 | 63% |
| `slow_guess` | S6 | 7/46 | 18/54 | 54% |

`slow_guess` defeats S3 completely and `delay_gap` defeats S6 completely. Both are still caught, by S1 and by S2 and S4 respectively, which is the argument for overlapping signals rather than an argument that the evasions failed.

`param_rename` is the interesting partial. It only evades S5 when it drops the query string entirely: the 33 `topic_only` variants are invisible to S5 and the 17 `renamed` ones still fire it, because an innocuous-looking key is still a key `/intranet/forum/new` has never carried. Renaming a parameter does not hide it from a baseline that knows the parameter names.

### Attribution is capped by the log, not by the detector

71 of 200 variants carry `own_ip_takeover`, where the session arrives from a host no baseline can attribute. The log contains no line naming the attacker, so the correlator reports the address and drops confidence to low. Of those 71, 8 are still named through the S6 chain and 63 are not, which puts the ceiling near 64%.

The measured 53% is lower because of a second group: 31 F2 variants where `delay_gap` silenced S6 and the victim never left her own host, so there is no `ip_owner` edge and no vector author either. Those incidents name the asset and the victim and decline to name an attacker.

**Nothing was blamed on the wrong person.** Across 200 detected variants, every attribution miss is a null field rather than a wrong name. That is the number worth saying out loud, because declining to name and naming the wrong colleague are the same miss in a rate and nothing alike in an investigation.

### Judge panel

`minny/api/routes_redteam.py` serves `GET /api/metrics`, `POST /api/redteam/generate` and `GET /api/blue/proposals`. Generation runs the real planner, renderer and critic through `generate_one`, so a judge's variant is the same object as one from `--seed 42`. A combination the access matrix cannot support is a 400 naming what is wrong rather than a silent substitution, and a target named explicitly is honoured for any sensitive file with an authorized reader and someone denied, not only the three confidential ones the random draw uses. Live injection waits on B's replay queue: the route looks for `routes_detect.enqueue_variant` on every request and returns `injected: false` with the reason until it exists.
