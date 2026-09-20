# Track A: forensics and the case file

**Owner:** A. **Branch:** `track/a-forensics`. **Milestones:** M0 parser, M1 case file, M9 demo and submission.

You are the critical path for the first 90 minutes and the voice of the project for the last three hours. Everything B and C build sits on your parquet file, and everything a judge believes comes from your case file.

## Checklist

- [x] **19:50** `logs.txt` located, SHA-256 posted to the team
- [x] **20:15** `pyproject.toml`, `.gitignore`, `minny/api/app.py` skeleton merged; contracts frozen
- [x] **21:00** `events.parquet`, `size_table.json`, `access_matrix.json`, `GET /api/events` merged (**C2, this unblocks B and C**)
- [x] **23:00** Findings F1 through F5 with evidence lines; first `case_file.json` merged
- [x] **01:00** Case file complete: timeline, unknowns, dismissed leads, all queries saved (**C4**)
- [ ] **01:00 onward** M9: Devpost draft, demo script, rehearsals
- [ ] **05:00** Backup video recorded
- [ ] **08:00** Submitted

## Before anything else, at 19:50

Three things, in this order:

1. **Get `logs.txt`.** It is not in the repo. `CSE_DATA_DIR=` in `docs/technical-spec/environment.example` is empty. Post its SHA-256 in the team channel; every derived artifact records that hash so we can prove later that we all used the same file.
2. **Ask the organizers whether more than one incident is planted.** If yes, M1 repeats per incident and you should know now, not at midnight.
3. **Create the shared skeleton** so nobody else has to touch a shared file all night: `pyproject.toml` (pandas or polars, pyarrow, fastapi, uvicorn, sse-starlette, pyyaml, pytest), `.gitignore` (`data/`, `*.parquet`, `.env`, `__pycache__/`, `node_modules/`), and `minny/api/app.py` importing all four routers by the names fixed in [00-CONTRACTS.md](00-CONTRACTS.md) section 12, wrapped so a missing router logs a warning instead of crashing the process.

## M0: parser and canonical events (target 21:00)

Ship `minny/parser.py` producing `data/events.parquet` to the column contract in 00-CONTRACTS.md section 1.

```
^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\S+)$
```

**Assert, do not hope.** Zero unparsed lines. Exactly 180,800 rows. `line` ascending with no gaps. If an assert fails, stop and post in chat before anyone builds on the output. A silently dropped line is a silently wrong case file.

Details that matter downstream:

- Timestamps are tz-aware at UTC−4. A naive datetime here becomes an off-by-four-hours bug in B's 72-hour correlation window, and you will find it at 03:00.
- Normalize exactly three template families: `/intranet/forum/view/{id}`, `/intranet/forum/edit/{id}`, `/assets/avatar_{id}.png`. Put the extracted number in `obj_id`. Adding a fourth after the freeze silently breaks B's baselines and C's mutations.
- Keep `raw` verbatim. It is what the judge sees when they click a claim, and re-serializing a line from parsed fields is how you end up showing evidence that does not match the file.
- `-` in the user field becomes `null`, not the string `"-"`.

Then emit the two derived files C depends on, both in 00-CONTRACTS.md sections 2 and 3:

- `data/size_table.json`: group on `(base, status)`, record the size where constant, list everything else under `variable_size_paths`. Without this, every synthetic line C renders is detectable by inspection and the stress test is theatre.
- `data/access_matrix.json`: per sensitive file, who got a `200` and who got a `403`. C needs it for `victim_swap` and `target_swap`.

Finish M0 with `GET /api/events?lines=` in `minny/api/routes_case.py`. It is 15 lines, D needs it for every drill-down in the UI, and it is the single most-used endpoint in the demo.

## M1: the case file (target 01:00)

**One saved, re-runnable query per finding, each returning line numbers.** Put them in `minny/casefile/queries.py` as named functions; `case_file.json` references them by name. No finding may exist as prose alone. The expected results below come from the dataset brief and have not been verified against the file. **Re-derive each one; where the data disagrees, the data wins and you post the correction.**

| Finding | Query | Expected lines |
|---|---|---|
| F1 user/IP binding broken | user/IP pairs outside each user's single baseline IP | 168311-168314, 168321-168326, 168343-168346 |
| F2 password guessing | consecutive 401s, same user and IP, gaps under 15s | the same two bursts, and **confirm zero other bursts in the whole file** |
| F3 tampered forum post | query keys on `/intranet/forum/new` other than `topic` | 168330, 168331, 168332 |
| F4 one-off privileged calls | globally unique templates | `/api/admin/role_update` 168336, `/assets/avatar_{id}.png` 168337 |
| F5 the exfiltration | first `200` on a path where this user previously had only 403s | 168338, david_m after 80+ denials |

F2's second half matters more than the first. "Two bursts in 180,800 lines and no others" is what makes the burst a finding rather than a coincidence, and it is the sentence that survives a skeptical judge.

**Post attribution (F6), and be honest about it.** david_m gets a `302` on `forum/new` at 168332 and views post 1042 three seconds later at 168333; sarah_j views 1042 at 168335 and `role_update` fires one second later at 168336. That chain is how we name David as the author. **The logs do not record post authorship.** Tag the finding as a heuristic, give it `confidence: "medium"`, and put the reason in `method` where the UI will render it. Volunteering this is worth more than defending it later.

**Dismissed leads are a deliverable, not a footnote.** Each needs the query that kills it:

- Off-hours access: routine here, including sarah_j pulling the same zip at 00:19 on 6 March from her own IP.
- The ~900 scattered 401s: no burst structure, spread across users and months.
- The ~5,300 403s: the access model denies constantly by design; volume is normal, a `403` becoming a `200` is not.

**Unknowns are a deliverable too.** How the login as sarah_j eventually succeeded. What post 1042 contained, since the logs record requests and never bodies. Who revoked david_m's access before the 27 March `403`. Ship all three in `unknowns`; U1 and U3 are exactly what the mailbox evidence in [00-CONTRACTS.md](00-CONTRACTS.md) section 11 may answer, so coordinate with D once `data/email_evidence.json` exists and add an email-corroborated finding if a message genuinely lines up. If it does not, leave the unknowns standing. An honest unknown reads better than a stretched claim.

**Done when** the UI renders the whole case file from `case_file.json` alone and every claim resolves to raw lines.

## M9: demo and submission (01:00 onward, protected)

You own the story. Start the Devpost draft at 01:00 while the others are still building, because at 05:00 you will be editing, not writing.

- **Devpost:** problem, findings, architecture, metrics *with methodology*, limitations stated plainly (single dataset, ten users, heuristic post attribution, detector tuned to this organization, seeded demo mailbox), credit to the prior fraud project as inspiration, source link.
- **Numbers come from `metrics.json` and nowhere else.** If C's number changed at 04:00, your slide changed at 04:00. Never a remembered figure.
- **Record the backup video by 05:00**, running the full three minutes against `?mock=1` so it cannot break.
- **Rehearse three times, timed.** The 60-second judge segment is the one that overruns.

The demo script is in [README.md](README.md). Two lines to land: *"They asked if there was funny business. There was."* and the close, *"We found the breach, then attacked our own detector hundreds of ways so it catches the next one."*

## M1 as built, and what the data said back

Everything below was re-derived from `data/events.parquet`. Rebuild and re-check it with:

```bash
export MINNY_DATA_DIR=/path/to/main/checkout/data
python -m minny.casefile.queries              # every saved query, with its lines and counts
python -m minny.casefile.build                # writes data/case_file.json
python -m minny.casefile.build --emit-fixture # and copies it into fixtures/mock/
python -m pytest tests/test_casefile.py -q
python web/verify_fixtures.py
```

### The findings, with the lines they actually returned

| ID | Query | Lines | The number that carries it |
|---|---|---|---|
| F1 | `ip_user_mismatch` | 168311-168314, 168321-168326, 168343-168346 | 14 lines out of 180,800 break the one-user-one-IP binding, all of them sarah_j on 10.0.8.45 |
| F2 | `auth_fail_burst` | 168311-168314, 168321-168326 | 2 bursts in the file and no third: of the other 889 failed logins, **not one pair** from the same user and IP is closer than 174 seconds, and there is not a single run of two |
| F3 | `tampered_forum_post` | 168330, 168331, 168332 | 3 of 9,083 forum posts carry a key other than `topic`, and `/intranet/forum/new` is the only path in the file that ever carries a query string |
| F4 | `globally_unique_templates` | 168336, 168337 | 2 of 27 templates occur once; the next rarest occurs 1,778 times |
| F5 | `first_success_after_denials` | 168338 | 77 denials before the download, 80 in total, 3 more once access closed again on 27 March |
| F6 | `anomalous_status` | 168330, 168331 | the only 400 and the only 500 in the file, both david_m's failed payloads |
| F7 | `post_attribution` | 168332, 168333 (+168335, 168336, 168339 as chain evidence) | 1 of 9,081 accepted posts is followed within 10s by its author opening a post |

Supporting queries the timeline cites: `denials_before_exfil` (168315 and 178028, the last denial before the download and the first one after it), `content_triggered_privileged_action` (168335, 168336), `vector_object_edits` (168339), `cover_download` (168340), `credential_mechanism_gap` (168326, 168343).

Dismissed leads: `offhours_confidential_access` (9 legitimate off-hours reads, lines 42768 to 162048), `scattered_auth_failures` (889 isolated 401s), `routine_denials` (5,324 denials).

### Four corrections the data forced

1. **F5 needs a threshold, and the case file says so.** "First 200 where every earlier attempt was a 403" returns **two** rows, not one. The second is sarah_j at line 370 on day one of the dataset: one denial, then 1,528 successes on the same file. That is an access grant landing, not a breach. The query takes `min_prior_denials` (default 5), keeps the rejected row in `stats.flips_below_threshold`, and the finding's `method` names it.
2. **david_m did not create post 1042.** Object 1042 first appears at **line 331 on 2025-08-01**, seven months before the incident, and carries 353 events. The brief and the contract example both say "created", and that is not in the data. What is in the data: he posts with a tampered parameter at 168332 and opens 1042 three seconds later at 168333, uniquely among 9,081 posts, and edits the same object 21 minutes after the download. F7 stays `confidence: medium` and says all of this in `method`.
3. **Off-hours access here is rare, not routine, and the lead dies on ownership instead.** The brief and the first case file both called it routine. The file says otherwise: **10 of 6,115** successful confidential reads fall in the 20:00-06:00 window, 0.16% of them. What clears the lead is whose they are. Nine are authorized readers on their own baseline machines and the tenth is the incident itself, line 168345, which the IP binding already names. Five are strictly after midnight and **exactly one of those touches the Q1 zip**: line 162048, sarah_j at 00:19 on 6 March from 10.0.5.12, a file she reads 1,528 times in this log. The contract's example line 161204 is `ashley_k GET /assets/app.js` and is not an off-hours confidential read at all. One window, 20:00-06:00, is stated in the lead and used everywhere; a rule built on it buys nine false positives and no new true one.
4. **77, not 80, precede the theft.** david_m collects 80 denials on the zip in total: 77 before line 168338, then 3 more from 27 March once the access closed again, first at line 178028. "Denied 80 times, then succeeded once" is the one phrasing to avoid, because it puts all 80 before the download. Both numbers are true; the case file uses each where it belongs, says which side of the download each falls on, and names the 3 reopened denials as the evidence behind U3. The timeline carries line 178028 as its last beat for the same reason.

### The additive fields, and why the fixture is generated now

`fixtures/mock/case_file.json` was written by hand from the same dataset and the two documents drifted: a differently worded verdict, 9 findings against 7, 14 timeline beats against 16, and an off-hours lead using 08:00-18:59 in one and 20:00-06:00 in the other. The demo runs on the fixture and live mode runs on the generated file, so the drift was invisible until someone flipped the switch.

`python -m minny.casefile.build --emit-fixture` now writes both. The fixture is a byte-for-byte copy of `data/case_file.json` and `fixtures/mock/events.json` is rewritten with the raw bytes of every line the document cites, read out of `data/logs.txt` and checked against the parsed `raw` column before it is written. Lines past the end of the real log are the red team's injected variant; they are carried across from the existing fixture untouched. **Do not hand edit the fixture.** If the UI needs a field it does not carry, add it to the generated file and re-emit.

The document carries these optional fields for the UI. All of them degrade to nothing if absent:

| Field | What it holds |
|---|---|
| `source` | `{file, lines, sha256}` for the provenance rail. Dropped entirely when `logs.txt` is not on the machine. |
| `verdict.basis` | One sentence on why the verdict should be believed, built from the same counts as F1, F4 and F6. |
| `timeline[].confidence` | `high` except the three beats that rest on a reading rather than a record: 168333, 168339, 168340. |
| `dismissed[].id`, `dismissed[].confidence` | D1 to D3, each `high`. |
| `actors.attacker`, `actors.victim` | `confidence`, `summary`, `stats` as `[{label, value}]` and `evidence_lines`. Every figure is read out of a saved query, including the denial counts, which the attacker card states in the order they happened. |

### For B and C

- The `query` column survives the parquet round trip as a **struct**, so every row carries every key the column ever saw with `None` where the parameter was absent. `bool(row["query"])` is therefore always true. Filter the Nones out; `minny.casefile.queries._query_keys` does it in one place.
- `casefile.queries` is importable on its own and every function takes an optional `events` frame, so a detector can reuse a forensic query rather than reimplementing it. `content_triggered_privileged_action` is S6 and `post_attribution` is S7 in all but name.
- Unknown U3 is the one most likely to be answered by the mailbox. `build.attach_email_evidence` already links a message to a finding when both cite the same line, and it never raises a finding's confidence.
