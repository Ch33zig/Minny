# Minny

Eight months of web logs from a ten-person company, one insider breach hidden in them, and a detector that gets attacked hundreds of ways to prove it would catch the next one.

## What this is

A company handed over 180,800 lines of access logs covering every page and file their ten employees opened between August 2025 and March 2026, and asked whether anyone was up to no good. Someone was.

**The case file** names the attacker, the victim, the asset and the method, and every claim in it expands to the exact log lines that prove it. It also lists the leads that looked suspicious and were not, each with the query that dismissed it, and the things the logs genuinely cannot answer.

**The detector** learns what normal looks like for each person, which machine they use, which files they can open, what they usually do, and raises one plain-English alarm when the pattern breaks. Related alarms collapse into a single incident, so an analyst reads one story instead of twenty warnings.

**The stress test** is the part that makes any of it believable. Catching a breach you were told about proves nothing, so a generator invents hundreds of variations of the same attack, slower password guessing, a different victim, renamed parameters, a lunchtime run, and injects them into the same month. The evaluation measures how many are caught and how often the detector cries wolf.

**The improvement loop** closes what the stress test opens. It reads an evasion that worked, writes a detection rule for it, and keeps the rule only if it passes three checks: it catches attacks generated after it was written, it adds nothing to a normal month, and it is silent across the seven months the system calls normal. Rules that fail are kept with the reason, because a gate that accepts everything is not a gate.

## Run it

```bash
pip install -e .
export MINNY_DATA_DIR=/path/to/data        # only needed from a git worktree
python -m minny.build_events               # parse logs.txt into the canonical artifacts
python -m minny.baselines.build            # fit per-user behaviour on Aug to Feb
python -m minny.detect.run                 # replay March, write alerts and incidents
python eval.py --seed 42                   # stress test, writes metrics.json
python -m minny.blue.run --seed 42         # propose rules, gate them, keep what passes
```

The front end needs no build step and no backend:

```bash
python web/serve.py                        # then open http://localhost:8080/?mock=1
```

`?mock=1` reads committed fixtures. Drop it to run against the live API (`uvicorn minny.api.app:app`).

The dataset itself is **not** in this repository. It is competition material and this repo is public, so `data/` is gitignored and shared out of band. Every artifact records the source SHA-256 so everyone can prove they used the same file.

## What the logs actually say

Full detail in [docs/handoff/GROUND-TRUTH.md](docs/handoff/GROUND-TRUTH.md), which overrides every other document where they disagree. The short version:

- Nine of the ten users appear on exactly one IP across eight months. **One account appears on two**, and the second is the attacker's workstation. That is arithmetic, not a heuristic.
- **Status 400 and 500 occur exactly once each** in 180,800 lines, and both are the attacker's failed payloads before the one that worked. He iterated.
- The attacker was **denied the confidential file 77 times, then succeeded once**, nineteen minutes after a privileged call fired from the victim's session one second after she opened a forum post.
- Three further denials follow twelve days later, once access closed again. Nobody knows who closed it; the logs do not record that.

## What we deliberately do not claim

The forum post used as the vector is a **seven month old thread** that all ten employees read and edit. Posting returns a redirect that never names the object it created, so the logs cannot show who planted anything. What they show is that the attacker submitted a post and opened that thread three seconds later, and edited it after the download. That is presence at the vector, not authorship, and the case file says so at medium confidence.

More broadly: this is an insider-threat detection method demonstrated on one organisation. Thresholds were chosen against this dataset. The stress test exists precisely to measure how far that tuning stretches before it breaks, rather than asserting that it generalises.

## Layout

```
minny/parser.py        Common Log Format parser and template normalisation
minny/build_events.py  Canonical events, response size table, access matrix
minny/casefile/        Saved queries, one per finding, and the case file builder
minny/baselines/       Per-user behaviour fitted strictly below the March cutoff
minny/detect/          Signals S1 to S8, correlator, replay engine, rule DSL
minny/redteam/         Attack families, mutation operators, renderer, critic
minny/eval/            Detection, attribution, false positives, time to detect
minny/blue/            Rule proposal and the three-part validation gate
minny/api/             One FastAPI app, one router per track
dist/, web/            Front end, no build step, fixtures or live API
docs/handoff/          Build plan, shared contracts, verified ground truth, design
```

## Design notes worth knowing

- **No signal reads email.** Mailbox records corroborate a finding and are capped at medium confidence, because headers are forgeable and we do not verify DKIM. Alerts stay reproducible from the parsed log alone, which is what makes the evaluation mean anything.
- **Explanations are generated from signal values, not written by a model.** An LLM may smooth wording; it may never add a fact. Every sentence traces to a field and a line number.
- **The LLM never writes a log line.** It picks parameters for attack variants; deterministic code renders everything, which is what keeps the output reproducible from a seed and safe to publish.
- **A proposed rule is parameters, never code.** Rules are tokenised, parsed into a fixed set of nodes, capped and walked by a comparator. There is no eval, no exec and no regular expression compiled from the file, because that file is written unattended.
- **A rule earns its place on attacks written after it.** The one that matches the literal payload from March catches the real incident perfectly and 0 of 40 variants that rename the parameter, so it is rejected and kept on display.
- **Baselines are fitted strictly below 2026-03-01.** The incident sits inside the held-out window. Fitting on all of it would enrol the attacker as an authorised reader of the file he took.
