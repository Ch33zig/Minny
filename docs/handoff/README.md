# Minny — build handoff

Four people, four branches, one merge target. Read this file, then read **only your own track file** and [00-CONTRACTS.md](00-CONTRACTS.md). Everything else is reference.

| File | Owner | Covers |
|---|---|---|
| [GROUND-TRUTH.md](GROUND-TRUTH.md) | A | **Read first.** Verified facts from the real dataset. Overrides every other document |
| [00-CONTRACTS.md](00-CONTRACTS.md) | A (frozen at 20:15) | Every JSON/parquet shape that crosses an owner boundary |
| [A-forensics-and-case-file.md](A-forensics-and-case-file.md) | A | M0 parser, M1 case file, M9 demo + Devpost |
| [B-detection.md](B-detection.md) | B | M2 baselines, M3 detector + correlator + API/SSE |
| [C-redteam-and-eval.md](C-redteam-and-eval.md) | C | M4 generator, M5 eval harness, M6 blue agent |
| [D-frontend-and-integrations.md](D-frontend-and-integrations.md) | D | M7 UI, M8 Composio/Slack/GitHub |

## The product, in plain English

A company gave us eight months of web logs — every page and file their ten employees opened — and asked whether anyone was up to no good. Someone was.

**Part 1, the case file.** David planted a booby-trapped forum post. Sarah, an admin, opened it, and her browser quietly granted David access to a confidential financial draft he was never allowed to see. Twenty minutes later he downloaded it. He had also been guessing her password from his own machine, and that night someone logged in as Sarah *from David's computer* and downloaded the same file again — cover. Every claim in our case file clicks through to the exact log lines that prove it, including the leads we dismissed: employees working late are not attackers. Where the logs go quiet — they record requests, never who authorized what — we pull corroborating records from the company mailbox: the permission-change notification names the person the log does not.

**Part 2, the watchdog.** A detector that learns what normal looks like per person — which machine, which files, what hours — and raises one plain-English alarm when the pattern breaks: *"Sarah's account just logged in from David's computer."* Related alarms collapse into a single incident, so an analyst reads one story instead of twenty warnings.

**Part 3, the stress test.** Catching David proves nothing; we already knew the answer. So an AI burglar invents hundreds of variations of his scheme — slower password guessing, a different victim, disguised posts, a lunchtime run — and slips them into the records. We measure catches and false alarms. When a variation slips through, an AI locksmith proposes a new rule, accepted only if it catches held-out variants it never saw, without crying wolf on normal days.

**The demo moment:** a judge plays the burglar, picks a victim and a trick, and watches the watchdog catch it in seconds. Then they try to sneak one past it.

## Clock reality — read this before you plan your night

Handoff written **Sat 19 Sep 2026, 19:30 EDT**. Submission **Sun 20 Sep 2026, 08:00 EDT**. That is **12.5 hours**, of which the last 3 are M9 (hardening, backup video, Devpost) and are protected. **Effective build window: 19:30 to 05:00, 9.5 hours.**

The milestone effort estimates in the original plan total roughly 8h for A, 8h for B, 12h for C, and 13h for D. C and D do not fit. Two cuts are therefore made *now*, not at 04:00 when panic makes them for us:

1. **No React/Next.js.** D extends the existing vanilla `dist/index.html` + `dist/styles.css` + `dist/app.js` shell, which already carries the layout and visual language. A framework rewrite costs 2 to 3 hours that buy nothing a judge can see.
2. **Sentry is out. ES|QL translation is out.** These are the top two entries in the plan's own cut order. The 2:00 PM sponsor-lock deadline has already passed, so whoever submitted the track selections should confirm at kickoff what was actually locked. If Sentry was locked in, it becomes D's *last* task after M8, never a prerequisite for anything.

**Never cut M1, M3, or M5.** The case file, the detector, and the reproducible numbers are the demo. Everything else is decoration.

If the real submission deadline is a different day, shift every clock time below by the same offset. The sequence does not change.

## Checkpoints

Every checkpoint is a merge to `main`. Show up with working code or say you are behind. Being behind is fine at 21:00 and fatal at 03:00.

| Time | Gate | What must be true |
|---|---|---|
| **19:50** C0 | Kickoff done | `logs.txt` located and its SHA-256 posted; contracts skimmed; branches cut; sponsor tracks confirmed |
| **20:15** C1 | Contracts frozen | 00-CONTRACTS.md merged. Changes after this need a ping, not a unilateral edit |
| **21:00** C2 | Data lands | A merges `events.parquet`, `size_table.json`, and the evidence endpoint. B and C stop working against fixtures |
| **23:00** C3 | Signals live | B merges S1 through S6 with the real incident firing. C merges 20+ critic-accepted variants. D renders the case-file view from real `case_file.json` |
| **01:00** C4 | End to end | Replay produces one incident naming david_m and sarah_j, visible in the UI. A finishes the case file and moves to M9 |
| **03:00** C5 | Numbers | `python eval.py --seed 42` writes `metrics.json`; the metrics panel renders it. The judge panel injects a variant into a live replay. M8 fires once or is cut |
| **05:00** C6 | Freeze | No new features. Seeds fixed, variants and metrics precomputed, LLM responses cached |
| **08:00** C7 | Submitted | Devpost live, backup video recorded, demo rehearsed three times |

## Working in parallel without stepping on each other

The point of the split below is that **no two people ever edit the same file**, so `git merge` has nothing to resolve.

### Branches

```
git checkout -b track/a-forensics     # A
git checkout -b track/b-detection     # B
git checkout -b track/c-redteam       # C
git checkout -b track/d-frontend      # D
```

Merge `main` into your branch **at the top of every hour**: `git fetch origin && git merge origin/main`. Push to `main` at each checkpoint, fast-forward or merge commit, never rebasing anyone else's history. If you are blocked on someone's output for more than 15 minutes, take their fixture from 00-CONTRACTS.md and keep moving.

### File ownership

| Path | Owner |
|---|---|
| `data/`, `minny/parser.py`, `minny/casefile/`, `minny/api/routes_case.py` | A |
| `minny/baselines/`, `minny/detect/`, `minny/api/app.py`, `minny/api/routes_detect.py` | B |
| `minny/redteam/`, `minny/eval/`, `minny/blue/`, `minny/api/routes_redteam.py`, `eval.py`, `detection-rules/rules.yaml` | C |
| `dist/`, `web/`, `fixtures/mock/`, `minny/integrations/`, `minny/api/routes_integrations.py` | D |
| `docs/handoff/<your letter>-*.md` | you |

`minny/api/app.py` imports all four routers **by fixed module name, written today, before any of them exist**. Create your router file with the agreed name and it is wired up. Nobody edits `app.py` again.

### Shared files, and how to touch them

| File | Owner | Rule |
|---|---|---|
| `pyproject.toml` or `requirements.txt` | A | Append one line at the end. Never reorder |
| `.env.example` | A | Append only. Real secrets live in untracked `.env` |
| `detection-rules/rules.yaml` | C | Append-only; the blue agent writes to the bottom |
| `docs/handoff/00-CONTRACTS.md` | A | After 20:15, propose in chat and let A make the edit |
| `docs/handoff/README.md` | A | Do not edit |
| `README.md` (root) | A, at M9 | Do not edit |

Add `data/`, `*.parquet`, `.env`, `__pycache__/`, and `node_modules/` to `.gitignore` in the first commit. The 180,800-line log file and the derived parquet never enter git; share them out of band and verify by SHA-256.

## Cut order, in the order we cut

Sentry, then ES|QL translation, then the GitHub PR (keep Slack), then the blue agent (keep the stress-test metrics), then judge-panel operators beyond two. Never M1, M3, or M5.

## Demo script — 3 minutes

1. **Case, 40s.** "They asked if there was funny business. There was." Walk the timeline, click one claim into raw log lines, show one dismissed lead.
2. **Watchdog, 40s.** Replay March; the incident card assembles itself alert by alert and names David.
3. **Judge's turn, 60s.** They build an attack; it gets caught. Invite them to evade it.
4. **Proof, 25s.** Detection by operator, false alarms per day, time to detect. Show the `csrf` rule rejected by the gate and a real rule accepted.
5. **Close, 15s.** "We found the breach, then attacked our own detector hundreds of ways so it catches the next one."

## Known blockers and unverified facts

These are honest gaps, not pessimism. Each has an owner and a checkpoint.

- ~~`logs.txt` is missing~~ **Resolved at Wave 0.** The dataset is in place, parsed, and verified: 180,800 lines, `sha256 9f773643…70575`. It is gitignored because this repository is public, so set `MINNY_DATA_DIR` in a worktree.
- ~~Line numbers are unverified~~ **Resolved at Wave 0.** Every line number in the brief checked out. The incident **date and several paths did not** — see [GROUND-TRUTH.md](GROUND-TRUTH.md), which overrides the brief and these documents wherever they disagree.
- **Post authorship is a heuristic.** The logs record no author for forum posts. We infer it from a `302` on `forum/new` followed within seconds by a view of the new post ID. Label it as a heuristic in the UI and say so on stage. Do not let it become the load-bearing claim.
- **No service is provisioned.** No OpenAI project, Elastic deployment, Composio project, Slack workspace, or GitHub rules repo was found in this repository. D's M8 starts from zero, so budget the OAuth round trip and make every integration fail soft.
- **The evidence mailbox is seeded by us, and we say so.** There is no real corporate mailbox for this dataset, so D seeds a demo account with messages matching the story timeline. The UI and the Devpost both label it a seeded demonstration mailbox. Mail headers are forgeable and we do not verify DKIM, which is why email corroborates a finding and never carries one alone — see [00-CONTRACTS.md](00-CONTRACTS.md) section 11.
- **Ask the organizers whether more than one incident is planted.** If yes, A repeats M1 for each.

## Relationship to `docs/technical-spec/`

That package (Draft 2, 19 September 2026) describes the same product at a larger scope: workspace accounts, PostgreSQL, durable job queues, a full Composio remediation lifecycle. **It is not the build plan for tonight.** It is the integration reference. Use it for the parts we are actually shipping and ignore the platform scaffolding.

| Need | Read | Who |
|---|---|---|
| Composio setup, exact tool slugs, webhook handling, idempotency | [04-COMPOSIO.md](../technical-spec/04-COMPOSIO.md) | D |
| Elastic mapping and ingestion, if Elastic is entered | [03-ELASTIC-AND-CSE.md](../technical-spec/03-ELASTIC-AND-CSE.md) sections 1 to 3 | D |
| Rule document shape, evaluation result shape | [rule.schema.json](../technical-spec/rule.schema.json), [evaluation.schema.json](../technical-spec/evaluation.schema.json) | C |
| Attack plan shape for the LLM's structured output | [attack-plan.schema.json](../technical-spec/attack-plan.schema.json) | C |
| Gmail connection and scopes, for the evidence pull and the alert send | [08-GMAIL-NOTIFICATIONS.md](../technical-spec/08-GMAIL-NOTIFICATIONS.md) sections 2 and 3 | D |
| Sentry, if it survives the cut | [05-FRONTEND-AND-SENTRY.md](../technical-spec/05-FRONTEND-AND-SENTRY.md) section 4 | D |
| The UI shell we are extending | `dist/index.html`, `dist/styles.css`, `dist/app.js` | D |

Skip entirely tonight: invite-only accounts, PostgreSQL, Alembic migrations, the durable job queue, the outbox, and Render deployment. We run from files, in one process.
