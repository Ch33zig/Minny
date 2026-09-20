# Verified ground truth

Derived from the real dataset at Wave 0, not from the brief. **Where this file and any other document disagree, this file wins.** Everything here was produced by a query you can re-run.

Source: `data/logs.txt` · 180,800 lines · `sha256 9f773643335352d8aa8cc9f07c5f92614b65c806f84c84790f56e4c652970575` · 2025-08-01 08:00:57 to 2026-03-31 18:00:26.

**Every one of the 180,800 lines carries `-0400`.** There is no daylight-saving split in this dataset, including for March dates that would be EST in a real US/Eastern log. Store the log's fixed offset; converting to a named zone re-interprets every pre-8-March line and prints a wall clock an hour off the raw evidence sitting beside it in the UI.

Rebuild every derived artifact with `python -m minny.build_events`.

## Corrections to the original brief

The brief's **line numbers are all correct**. Two other things are not.

| The brief said | The data says |
|---|---|
| Incident on 27 March | **13-15 March 2026** |
| `/files/q1_draft_CONFIDENTIAL.zip` | `/finance/reports/q1_draft_CONFIDENTIAL.zip` |
| `/intranet/login` | `/api/auth/login` |
| `/intranet/dashboard` | `/dashboard` |
| `/intranet/logout` | `/logout` |

Forum and avatar paths are as described: `/intranet/forum/new`, `/intranet/forum/view/{id}`, `/intranet/forum/edit/{id}`, `/assets/avatar_{id}.png`, `/api/admin/role_update`.

## The ten users, and the one anomaly

Nine users appear on exactly one IP across eight months. `sarah_j` is the only user who ever appears on two.

| User | IP |
|---|---|
| amanda_l | 10.0.8.22 |
| ashley_k | 10.0.7.11 |
| chris_b | 10.0.6.34 |
| david_m | 10.0.8.45 |
| jessica_w | 10.0.6.21 |
| joshua_c | 10.0.8.50 |
| matthew_r | 10.0.7.15 |
| michael_t | 10.0.5.88 |
| nicole_h | 10.0.9.05 |
| sarah_j | 10.0.5.12 **and 10.0.8.45 (david_m's)** |

That second row is the whole of signal S1. In 180,800 lines there is exactly one user/IP binding violation, and it belongs to the victim on the attacker's machine. This is arithmetic, not a heuristic. Say it that way on stage.

## Status distribution

| Status | Count | Size |
|---|---|---|
| 200 | 140,069 | varies |
| 302 | 34,506 | 0 |
| 403 | 5,324 | 245 |
| 401 | 899 | 88 |
| **500** | **1** | 1024 |
| **400** | **1** | 512 |

**400 and 500 occur exactly once each in the entire file, and both are David's failed attack payloads** (lines 168330 and 168331). A globally unique status code is a stronger and simpler signal than the "globally unique template" the brief proposed. This justifies adding **S8 `anomalous_status`**.

## The incident, line by line

All timestamps 2026, UTC−4.

| Line | Time | Who | What | Status |
|---|---|---|---|---|
| 168311-168314 | 13 Mar 23:10:19-23:10:32 | sarah_j **from 10.0.8.45** | 4 failed logins, gaps 6s/3s/4s | 401 |
| 168315 | 14 Mar 09:19:15 | david_m | denied the Q1 zip | 403 |
| 168321-168326 | 14 Mar 22:11:26-22:11:39 | sarah_j **from 10.0.8.45** | 6 failed logins, gaps 4s/2s/3s/2s/2s | 401 |
| 168330 | 15 Mar 09:20:20 | david_m | `forum/new?topic=lunch_menu&payload=csrf_test` | **500** |
| 168331 | 15 Mar 09:42:35 | david_m | `forum/new?topic=q1_updates&action=csrf_role_update` | **400** |
| 168332 | 15 Mar 10:18:52 | david_m | `forum/new?topic=parking_issues&script=success` | 302 |
| 168333 | 15 Mar 10:18:55 | david_m | opens `forum/view/1042`, 3s later | 200 |
| 168335 | 15 Mar 11:07:56 | sarah_j | views `forum/view/1042` | 200 |
| 168336 | 15 Mar 11:07:57 | sarah_j | `POST /api/admin/role_update`, **1s later** | 200 |
| 168337 | 15 Mar 11:07:59 | sarah_j | `/assets/avatar_1042.png` | 200 |
| 168338 | 15 Mar 11:26:59 | david_m | **takes the Q1 zip**, 19 min after escalation | 200 |
| 168339 | 15 Mar 11:48:01 | david_m | edits post 1042 (cleanup) | 302 |
| 168340 | 15 Mar 12:34:21 | david_m | `/finance/templates/expense.docx` | 200 |
| 168343-168346 | 15 Mar 22:29:43-22:33:40 | sarah_j **from 10.0.8.45** | login, dashboard, **zip again**, logout | 200/302 |

Three payload attempts, two of which are the only 400 and 500 in the file, then one that works. David iterated. That is a better story than the brief's single post, and it is in the data.

### Post 1042 is NOT David's post (corrected)

The brief, and the first draft of this file, said David created post 1042. **The data says otherwise and the claim has been removed everywhere.**

Object 1042 first appears at **line 331, 1 August 2025**, seven months before the incident. It carries **353 events**, is read by **all ten accounts** (30-40 views each), and has been **edited 112 times**, including 13 times by david_m as ordinary use. It is a long-running, popular thread.

`/intranet/forum/new` returns a 302 that **does not name the object it created**. The log therefore cannot tell us what David's successful POST at 168332 produced. What it does show is that he opened 1042 three seconds later, and edited it 21 minutes after the download.

So the defensible chain is:

1. David sent three abnormal `forum/new` requests; two produced the only 400 and 500 in the file. **Strong.**
2. He opened 1042 three seconds after the one that succeeded. **Timing, not authorship.**
3. Sarah opened 1042 and one second later her account made the only privileged call in the file. **Strong.**
4. David then read a file he had been denied 77 times. **Strong.**

1042 is the vector by **temporal association**. Anyone saying "David planted the post" on stage is asserting something the logs do not contain. Say "David was at the vector immediately before and after": it is just as damning and it survives cross-examination.

## Off-hours access, and why it is a dismissed lead rather than a finding

Four confidential reads fall outside business hours across eight months. Every one is an authorized reader on their own workstation, so the pattern is ordinary. **Exactly one of them touches the Q1 zip**: sarah_j at 00:19 on 6 March from 10.0.5.12, line 162048.

Do not describe after-hours downloads of this file as "routine" on stage. One is not routine. The defensible sentence is that off-hours access happens here and every instance outside the incident belongs to someone entitled to the file, working from their own machine.

## Access model

Fitted on the pre-March window, so the attack cannot enrol the attacker as an authorized reader. Full detail in `data/access_matrix.json`.

| Path | Authorized | Denied |
|---|---|---|
| `/finance/reports/q1_draft_CONFIDENTIAL.zip` | nicole_h, sarah_j | 8 others incl. david_m |
| `/finance/reports/budget_v2_CONFIDENTIAL.xlsx` | sarah_j | 9 |
| `/hr/directory_full_CONFIDENTIAL.csv` | michael_t | 9 |
| `/exec/board_deck.pptx` | nicole_h | 9 |
| `/finance/reports/public_summary.pdf` | david_m | 9 |
| `/finance/templates/expense.docx` | david_m | 9 |
| `/hr/policies_2026.pdf` | michael_t | 9 |
| `/it/scripts/backup.sh` | amanda_l | 9 |

**`david_m` was denied the Q1 zip 77 times, then succeeded exactly once**, on line 168338. Three further denials follow on 27 March once access closed again (line 178028), which is the evidence behind unknown U3, so the whole-file count is 80. `sarah_j` succeeded 1,528 times and `nicole_h` 1,532, which is what ordinary authorized use looks like.

Three confidential files with three different authorized sets gives C real material for `target_swap` and `victim_swap`.

## Templates

27 distinct templates after normalization. Two of them occur **exactly once in the whole file**:

- `/api/admin/role_update`: line 168336
- `/assets/avatar_{id}.png`: line 168337

Everything else appears between 1,778 and 18,385 times.

## Consequences for the build

1. **Baseline cutoff is `2026-03-01T00:00:00-04:00`**, compared as an aware datetime, never as a string. It shares the log's fixed offset so it means midnight as the log writes it. The 13-15 March incident sits inside the held-out window, as intended.
2. **Add S8 `anomalous_status`**: a status that occurs fewer than N times globally. Catches 168330 and 168331, the reconnaissance David did before the payload that worked.
3. **`size_table.json` has 102 fixed-size and 85 variable-size paths.** Forum views are not constant (3105 vs 3371 bytes), so C's renderer must sample a real observed size for those rather than inventing one.
4. **The `csrf` rejection demo works on real strings.** The payloads literally contain `payload=csrf_test`, `action=csrf_role_update`, `script=success`, so a rule matching `csrf` catches the original perfectly and dies on `param_rename` variants exactly as planned.
5. **`data/` is gitignored**: public repo, competition dataset. Set `MINNY_DATA_DIR` to the main checkout's `data/` when working in a worktree.
