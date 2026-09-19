# Shared contracts

Owner: **A**. Frozen at **20:15**. After that, propose changes in chat and let A edit; a unilateral change here breaks three other people at once.

These are the only shapes that cross an owner boundary. Everything inside your own module is yours. Every example below is a valid fixture: **D copies each JSON block verbatim into `fixtures/mock/` in the first commit** and builds the entire UI against them, so the front end never waits on anyone.

Rules that apply to all of them:

- **`line` is the universal event ID.** 1-indexed line number in the original `logs.txt`. Every alert, finding, incident, and variant refers to evidence by line number, and any of them can be resolved to raw text through `GET /api/events`.
- **Logs are primary evidence; email is corroborating evidence.** Anything sourced from the mailbox lives in a separate `evidence_emails` array and can raise a claim's richness but never its confidence above `medium` on its own. See section 13.
- **Timestamps are ISO 8601 with offset**, preserving the dataset's UTC−4: `2026-03-27T14:32:07-04:00`. Never serialize a naive datetime.
- **Unknown is `null`, never `0` or `""`.** A missing IP owner is `null`; it is not "unknown".
- **Additive changes only after the freeze.** Adding a field is free, renaming one is not.

## 1. `data/events.parquet` — produced by A (M0)

One row per log line, 180,800 rows. Produced by A, read by B, C, and the evidence endpoint.

| Column | Type | Notes |
|---|---|---|
| `line` | int32 | 1-indexed event ID, ascending, no gaps |
| `raw` | string | The original line, byte-for-byte, for evidence display |
| `ip` | string | Source IP |
| `user` | string | Username, or `null` where the log has `-` |
| `ts` | timestamp[us, tz=-04:00] | Timezone-aware |
| `method` | string | GET / POST |
| `path` | string | Full path including query string |
| `base` | string | Path with the query string stripped |
| `query` | map<string,string> | Parsed query parameters; empty map when absent |
| `status` | int16 | HTTP status |
| `size` | int64 | Response bytes |
| `template` | string | `base` with numeric IDs normalized |
| `obj_id` | int64 | The number extracted by normalization, else `null` |

Templates are normalized to exactly these forms: `/intranet/forum/view/{id}`, `/intranet/forum/edit/{id}`, `/assets/avatar_{id}.png`. Every other path is its own template. **The normalization list is a contract** — B keys baselines on templates and C keys mutations on them, so if A adds a fourth normalization after the freeze, both break silently.

Parser regex, applied to every line with zero tolerance for failure:

```
^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\S+)$
```

Assert 0 unparsed lines and assert the row count is 180,800. If either assert fails, stop and post in chat before anyone builds on the output.

## 2. `data/size_table.json` — produced by A (M0), consumed by C

The realism constraint for the red team. Every synthetic line C renders must carry a status/size pair that already occurs in the real data, or a judge diffing the file spots the forgery instantly.

```json
{
  "generated_from": "logs.txt",
  "sha256": "<sha256 of logs.txt>",
  "by_status": {
    "401": 88,
    "403": 245,
    "302": 0
  },
  "by_path": {
    "/intranet/login": { "200": 128, "401": 88 },
    "/intranet/logout": { "302": 0 },
    "/intranet/forum/new": { "302": 112 },
    "/intranet/forum/edit": { "302": 112 },
    "/files/q1_draft_CONFIDENTIAL.zip": { "200": 8459200, "403": 245 }
  },
  "variable_size_paths": ["/intranet/dashboard"]
}
```

A generates this by grouping the parsed events on `(base, status)` and recording the size where it is constant. Any `(base, status)` pair with more than one observed size goes in `variable_size_paths`, and C must sample a real observed size for those rather than inventing one.

## 3. `data/access_matrix.json` — produced by A (M0), consumed by C

Who is actually allowed to read what, derived from the data rather than assumed. C needs it for `victim_swap` and `target_swap`, because a variant whose victim was never authorized is incoherent and the critic must reject it.

```json
{
  "/files/q1_draft_CONFIDENTIAL.zip": {
    "size": 8459200,
    "authorized": ["sarah_j", "nicole_h"],
    "denied": ["david_m", "michael_r", "jessica_l"]
  }
}
```

`authorized` is every user with at least one `200` on that path in the baseline window; `denied` is every user with a `403` and no `200`.

## 4. `data/baselines.json` — produced by B (M2), consumed by B and C

Fit on `ts < 2026-03-01` only. March is held out and must never touch this file, or the evaluation is worthless.

```json
{
  "fit_window": { "start": "2025-08-01T00:00:00-04:00", "end": "2026-03-01T00:00:00-04:00" },
  "event_count": 168000,
  "ip_owner": { "10.0.5.12": "sarah_j", "10.0.8.45": "david_m" },
  "users": {
    "sarah_j": {
      "ips": ["10.0.5.12"],
      "allowed_paths": ["/intranet/dashboard", "/files/q1_draft_CONFIDENTIAL.zip", "/api/admin/role_update"],
      "denied_paths": ["/files/hr_salaries.csv"],
      "templates_seen": ["/intranet/dashboard", "/intranet/forum/view/{id}"],
      "hour_hist": { "0": 3, "9": 412, "14": 380 },
      "auth_fail": { "count": 14, "median_gap_s": 3600, "min_gap_s": 240 }
    }
  },
  "global": {
    "template_freq": { "/intranet/dashboard": 41022, "/api/admin/role_update": 0 },
    "param_keys": { "/intranet/forum/new": ["topic"], "/intranet/search": ["q"] },
    "privileged_templates": ["/api/admin/role_update"]
  }
}
```

`allowed_paths` means at least one `200`. `denied_paths` means at least one `403` and zero `200`s. `privileged_templates` is everything under `/api/admin/` plus any template seen fewer than *k* times globally that returns `200` to a `POST`; B picks and records *k*.

`hour_hist` exists for explanation text only. **It never triggers an alert** — the dataset contains legitimate off-hours access, including sarah_j downloading the same confidential zip at 00:19 on 6 March from her own IP. Alerting on hours would fire on her and make the demo an argument instead of a story.

Load target: under one second, and it answers "has user X ever succeeded on Y, used IP Z, or sent param P to template T" without a scan.

## 5. Alert — produced by B (M3), consumed by B's correlator, C's eval, D's UI

One alert per signal firing on one event.

```json
{
  "alert_id": "a_0f3c21",
  "ts": "2026-03-27T14:32:07-04:00",
  "signal": "S1",
  "signal_name": "ip_mismatch",
  "severity": "high",
  "user": "sarah_j",
  "ip": "10.0.8.45",
  "ip_owner": "david_m",
  "template": "/intranet/login",
  "obj_id": null,
  "value": { "known_ips": ["10.0.5.12"], "months_observed": 7 },
  "evidence_lines": [168343],
  "explanation": "sarah_j logged in from 10.0.8.45, which belongs to david_m. She has used only 10.0.5.12 in 7 months.",
  "incident_id": "inc_7b21e0"
}
```

Signal IDs are fixed: `S1` ip_mismatch, `S2` first_success_on_denied, `S3` auth_fail_burst, `S4` novel_template, `S5` unexpected_params, `S6` content_triggered_privileged_action, `S7` post_authorship. **S7 never emits an alert** — it is supporting evidence that the correlator reads for attribution. Severity is `low`, `medium`, or `high`. `incident_id` is `null` until the correlator claims it.

Explanations are **template-generated from signal values**. An LLM may smooth the wording; it must not add a fact that is not in `value` or `evidence_lines`. This is the rule that keeps the demo defensible under questioning.

## 6. Incident — produced by B (M3), consumed by C, D, and Slack

Alerts sharing an entity (user, IP, IP owner, `obj_id`, or target file) within a rolling 72-hour window collapse into one incident.

```json
{
  "incident_id": "inc_7b21e0",
  "opened_ts": "2026-03-27T13:58:11-04:00",
  "last_ts": "2026-03-27T22:04:55-04:00",
  "severity": "high",
  "status": "open",
  "title": "david_m escalated his own access through a forum post and took the Q1 confidential draft",
  "attacker": { "user": "david_m", "ip": "10.0.8.45", "confidence": "high", "basis": ["S1", "S6", "S7"] },
  "victim": { "user": "sarah_j", "confidence": "high", "basis": ["S6", "S1"] },
  "asset": "/files/q1_draft_CONFIDENTIAL.zip",
  "vector": { "template": "/intranet/forum/view/{id}", "obj_id": 1042 },
  "narrative": [
    { "ts": "2026-03-27T13:58:11-04:00", "text": "david_m posted to the forum with unusual query parameters.", "lines": [168330, 168331, 168332] },
    { "ts": "2026-03-27T14:12:40-04:00", "text": "sarah_j viewed post 1042, and one second later her account performed an admin role update.", "lines": [168335, 168336] },
    { "ts": "2026-03-27T14:32:07-04:00", "text": "david_m downloaded a file he had been denied 80+ times before.", "lines": [168338] }
  ],
  "alerts": ["a_0f3c21"],
  "evidence_lines": [168330, 168331, 168332, 168335, 168336, 168338, 168343],
  "evidence_emails": ["gmail:18f2c9a1b4d7"],
  "labels": { "synthetic": false, "variant_id": null }
}
```

Role resolution: the **attacker** is the IP owner behind `S1` alerts and the author of any `S6` vector post per `S7`. The **victim** is the account whose session performed the privileged action, or that was logged into from the wrong IP. When they conflict, prefer the `S6` chain and lower `confidence` to `medium`.

`labels.synthetic` is `true` and `variant_id` is set only when C injected the events. C's eval reads these; D's UI shows a synthetic badge so nobody on stage mistakes an injected variant for the real breach.

## 7. `case_file.json` — produced by A (M1), consumed by D

The UI renders the entire case file from this file alone, with no other source.

```json
{
  "case_id": "minny-2026-q1",
  "title": "Unauthorized access to the Q1 confidential draft",
  "window": { "start": "2025-08-01T00:00:00-04:00", "end": "2026-03-31T23:59:59-04:00" },
  "verdict": {
    "summary": "david_m escalated his own privileges through a forum post viewed by sarah_j, then downloaded the Q1 confidential draft and re-downloaded it that night from his own machine using her account.",
    "confidence": "high"
  },
  "actors": {
    "attacker": { "user": "david_m", "ip": "10.0.8.45" },
    "victim": { "user": "sarah_j", "ip": "10.0.5.12" },
    "asset": "/files/q1_draft_CONFIDENTIAL.zip",
    "vector": { "obj_id": 1042, "template": "/intranet/forum/view/{id}" }
  },
  "findings": [
    {
      "id": "F1",
      "claim": "sarah_j's account was used from david_m's workstation.",
      "confidence": "high",
      "method": "Every user maps to exactly one source IP across seven months. These lines break that binding.",
      "evidence_lines": [168343, 168344, 168345, 168346],
      "evidence_emails": [],
      "query": "casefile.queries.ip_user_mismatch"
    },
    {
      "id": "F7",
      "claim": "david_m was granted access to the finance group at 14:13 on 27 March, one second after sarah_j viewed post 1042.",
      "confidence": "medium",
      "method": "The log shows sarah_j's account calling /api/admin/role_update. The mailbox shows the resulting automated notification, which names the grantee the log does not record.",
      "evidence_lines": [168336],
      "evidence_emails": ["gmail:18f2c9a1b4d7"],
      "query": "casefile.queries.privileged_action_with_mail_corroboration"
    }
  ],
  "timeline": [
    { "ts": "2026-03-27T13:58:11-04:00", "line": 168332, "actor": "david_m", "action": "Created forum post 1042 carrying non-standard query parameters", "note": "Authorship is inferred, see U2" }
  ],
  "unknowns": [
    { "id": "U1", "text": "How the login as sarah_j eventually succeeded. The logs show failures and then a success, with no mechanism recorded." },
    { "id": "U2", "text": "Post contents. The logs record requests, never bodies, so the payload is inferred from its effect." },
    { "id": "U3", "text": "Who revoked david_m's access before the 403 on 27 March." }
  ],
  "dismissed": [
    {
      "lead": "Employees accessing files after midnight",
      "why": "Off-hours access is routine here, including sarah_j pulling this same zip at 00:19 on 6 March from her own IP.",
      "query": "casefile.queries.offhours_access",
      "evidence_lines": [161204]
    }
  ]
}
```

`confidence` is `high`, `medium`, or `low` everywhere it appears, and the UI renders it as a visible label. Every `query` names a saved, re-runnable query in A's module; nothing in this file is hand-typed prose about data nobody can re-derive.

## 8. Variant label — produced by C (M4), consumed by C's eval and D's judge panel

```json
{
  "variant_id": "v_0042",
  "seed": 42,
  "family": "F2",
  "family_name": "content_privilege_escalation",
  "persona": "careful_insider",
  "operators": ["slow_guess", "param_rename"],
  "attacker": "michael_r",
  "victim": "nicole_h",
  "target": "/files/q1_draft_CONFIDENTIAL.zip",
  "injected_lines": [180801, 180802, 180803],
  "first_malicious_line": 180801,
  "first_malicious_ts": "2026-03-14T11:20:00-04:00",
  "critic": { "accepted": true, "checks_passed": ["format", "monotonic_ts", "size_table", "authorization", "operators_present"], "rejected_reason": null }
}
```

Families are fixed: `F1` credential_takeover, `F2` content_privilege_escalation, `F3` cover_download, `F4` full_chain. Operator names are fixed and are the keys the metrics table reports on: `slow_guess`, `own_ip_takeover`, `param_rename`, `victim_swap`, `target_swap`, `business_hours`, `delay_gap`, `no_cleanup`, `no_cover_download`.

Injected lines are numbered above 180800 so a synthetic event can never collide with a real event ID.

## 9. `metrics.json` — produced by C (M5), consumed by D

Everything said on stage comes from this file, and this file comes from one command.

```json
{
  "generated_at": "2026-09-20T03:04:00-04:00",
  "command": "python eval.py --seed 42",
  "seed": 42,
  "rule_revision": "rules.yaml@a1b2c3d",
  "variants": { "total": 212, "by_family": { "F1": 54, "F2": 61, "F3": 49, "F4": 48 } },
  "detection": {
    "overall": 0.0,
    "by_operator": { "slow_guess": { "n": 38, "detected": 0, "rate": 0.0 } },
    "by_family": { "F2": { "n": 61, "detected": 0, "rate": 0.0 } }
  },
  "attribution": { "n_detected": 0, "attacker_correct": 0, "victim_correct": 0, "both_correct_rate": 0.0 },
  "false_positives": {
    "benign_stream": "March 2026 minus labeled incident lines",
    "alerts_total": 0,
    "incidents_total": 0,
    "alerts_per_day": 0.0,
    "by_day": { "2026-03-01": 0 }
  },
  "time_to_detect": { "median_log_seconds": 0, "p90_log_seconds": 0, "wallclock_ms_per_event": 0.0 },
  "real_incident": { "detected": true, "attribution_correct": true, "alert_count": 0 }
}
```

The numeric zeros are placeholders in the fixture so D can render the layout; real numbers land at C5. A variant counts as **detected** when an incident contains at least one of its `injected_lines`. Time to detect is log-time from `first_malicious_ts` to the first alert, reported separately from wall-clock processing latency.

## 10. Rule DSL — C (M6), stored in `detection-rules/rules.yaml`

Parsed by a small grammar. No free-form code execution, ever, including from an LLM.

```yaml
- id: R003
  name: slow credential guessing from a foreign host
  severity: high
  proposed_by: blue_agent
  created_ts: "2026-09-20T02:14:00-04:00"
  when: count(status=401, user=$u, window=24h) >= 5 AND ip_owner != $u
  explain: "{user} failed to log in {count} times in 24 hours from {ip}, which belongs to {ip_owner}."
  gate:
    heldout_detection: { threshold: 0.6, measured: 0.71, pass: true }
    benign_fp_delta: { budget: 2, measured: 0, pass: true }
    baseline_window_hits: { required: 0, measured: 0, pass: true }
    accepted: true
```

Grammar:

```
expr   := term (("AND" | "OR") term)*
term   := "NOT"? (predicate | "(" expr ")")
predicate := count "(" args ")" op number
           | field op value
count_args := (status=<int> | signal=<S1..S7>)? ("," field "=" value)* ("," "window=" duration)?
field  := user | ip | ip_owner | template | obj_id | status | signal
op     := "==" | "!=" | ">=" | "<=" | ">" | "<"
value  := "$u" | "$ip" | quoted-string | number
duration := <int>("s"|"m"|"h"|"d")
```

`$u` and `$ip` bind to the subject of the event under evaluation. Depth is capped at 4 and node count at 30. A rule that fails to parse is rejected before the gate runs, and the parse error is shown in the UI.

## 11. Email evidence — pulled by D (M8) through Composio Gmail, consumed by A and B

Logs answer *what happened*. They are silent on *who authorized it*. The mailbox often holds exactly the missing sentence: a permission-change notification naming the grantee, an access-request approval, a group or cluster membership change, a credential reset, a data-export confirmation. Our case file has three open unknowns (U1, U2, U3) and at least two of them are the kind of thing an automated notification email answers outright.

So Gmail is **both** an output channel and an evidence source. This section covers the evidence direction.

### The object

```json
{
  "evidence_id": "gmail:18f2c9a1b4d7",
  "source": "gmail",
  "message_id": "18f2c9a1b4d7",
  "thread_id": "18f2c9a1b4d0",
  "ts": "2026-03-27T14:13:02-04:00",
  "from": "no-reply@intranet.example.com",
  "to": ["sarah.j@example.com"],
  "subject": "Role updated: david.m added to finance-confidential",
  "snippet": "david.m was added to the group finance-confidential by sarah.j at 14:13 EDT.",
  "category": "permission_change",
  "matched_entities": { "users": ["david_m", "sarah_j"], "assets": [], "groups": ["finance-confidential"], "ips": [] },
  "linked_lines": [168336],
  "link_basis": ["entity_match", "time_proximity_60s"],
  "confidence": "medium",
  "permalink": "https://mail.google.com/mail/u/0/#inbox/18f2c9a1b4d7"
}
```

`category` is one of `permission_change`, `access_request`, `access_revoked`, `group_membership`, `credential_reset`, `data_export`, `security_alert`, or `other`. D classifies deterministically from a keyword and sender map first; an LLM may only refine `other`, and may never invent `matched_entities`.

### Linking rules

An email attaches to a finding or incident when **both** hold:

1. **Entity match.** A username, email local-part, asset filename, group name, or IP from the incident appears in the subject, snippet, sender, or recipients. Matching is exact on a normalized token, not substring — `david_m`, `david.m`, and `david.m@example.com` all normalize to `david_m`, while "davidson" does not.
2. **Time proximity.** The message timestamp falls inside the incident window widened by 24 hours on each side.

`link_basis` records which rules fired, so the UI can show why an email is attached. An email that matches on time alone is not evidence and is not attached.

### Confidence discipline

Email evidence **corroborates; it never carries a claim by itself**. A finding whose `evidence_lines` is empty and whose `evidence_emails` is non-empty is capped at `confidence: "medium"` and the UI must render it as *"supported by mailbox records only"*. Mail headers are trivially forgeable and we did not verify DKIM. Say that on stage if asked, before someone else says it.

Email never feeds a detector signal. No S-signal reads the mailbox; alerts stay reproducible from `events.parquet` alone, which is what keeps M5's numbers meaningful.

### Scope, privacy, and failure

- **Read-only.** Gmail read scope for the evidence path. The send scope for notifications is a separate grant, and the UI shows them as two independent capabilities.
- **Bounded queries only.** Fixed app-coded searches over a fixed window — `newer_than:`, plus a sender allowlist and a subject keyword set. Never a free-text query built from LLM output, and never a full mailbox crawl.
- **Store headers and snippet, not bodies.** Nothing beyond the fields above is persisted, and **no email content ever leaves the app** — not into a GitHub issue, not into a PR body, not into Slack. Those carry a Minny evidence link instead. This matches the existing rule in [04-COMPOSIO.md](../technical-spec/04-COMPOSIO.md) section 7 about never publishing raw source records.
- **Fails soft, always.** No Gmail connection, an expired token, or a rate limit changes nothing about the case file, the detector, the incidents, or the metrics. The UI hides the corroboration strip and the demo continues. Nothing on the critical path may `await` the mailbox.
- **The demo mailbox is seeded, and we say so.** No real corporate mailbox exists for this dataset. D seeds a demo account with 5 or 6 messages matching the story timeline, and both the UI and the Devpost writeup label it a seeded demonstration mailbox. Do not let a judge discover that on their own.

## 12. HTTP API

One FastAPI process. `minny/api/app.py` is written by B **at 20:15** and imports all four routers by these exact names, before they exist. Create your file, get wired up, and nobody touches `app.py` again.

| Method | Path | Router (owner) | Returns |
|---|---|---|---|
| GET | `/api/case_file` | `routes_case` (A) | `case_file.json` |
| GET | `/api/events?lines=1,2,3` | `routes_case` (A) | `[{line, raw, ts, user, ip, method, path, status, size}]`, max 200 lines |
| GET | `/api/baselines` | `routes_detect` (B) | `baselines.json` |
| GET | `/api/incidents` | `routes_detect` (B) | Incident array, newest first |
| GET | `/api/incidents/{id}` | `routes_detect` (B) | One incident with its alerts inlined |
| POST | `/api/replay/control` | `routes_detect` (B) | `{action: start\|pause\|reset, speed_hours_per_second, from, to}` |
| GET | `/api/stream` | `routes_detect` (B) | SSE, see below |
| POST | `/api/redteam/generate` | `routes_redteam` (C) | Judge panel: `{attacker, victim, target, operators[], persona}` to a variant label, injected into the live replay |
| GET | `/api/metrics` | `routes_redteam` (C) | `metrics.json` |
| GET | `/api/blue/proposals` | `routes_redteam` (C) | Proposed rules with gate results, accepted and rejected |
| POST | `/api/integrations/test` | `routes_integrations` (D) | Fires one Slack message, returns delivery status |
| POST | `/api/integrations/gmail/sync` | `routes_integrations` (D) | Runs the bounded mailbox queries, upserts `data/email_evidence.json`, returns counts |
| GET | `/api/evidence/email?ids=gmail:...` | `routes_integrations` (D) | Resolves evidence IDs to the objects in section 11, max 50 |

Errors are `{"error": {"code": "...", "message": "..."}}` with a real HTTP status. A missing `/api/*` route returns JSON 404, never `index.html`.

### SSE envelope on `/api/stream`

Every frame is one JSON object on one `data:` line:

```json
{ "type": "alert", "seq": 1042, "ts": "2026-03-27T14:32:07-04:00", "data": { } }
```

`type` is one of `event`, `alert`, `incident`, `replay_state`, or `heartbeat`. `data` holds the object from the matching section above; `replay_state` carries `{running, speed_hours_per_second, cursor_ts, events_emitted}`. A heartbeat every 15 seconds keeps proxies from closing the stream. `seq` increases monotonically so the UI can detect a gap after a reconnect.

## 13. Fixtures

D creates `fixtures/mock/` in the first commit from the blocks above:

```
fixtures/mock/case_file.json
fixtures/mock/incidents.json        # array of 2: the real one, one synthetic
fixtures/mock/alerts.json           # array of 6, one per signal S1-S6
fixtures/mock/baselines.json
fixtures/mock/metrics.json
fixtures/mock/blue_proposals.json   # one accepted, one rejected (the csrf rule)
fixtures/mock/events.json           # 12 raw lines for the evidence drill-down
fixtures/mock/email_evidence.json   # 5 messages, one per category used in the story
fixtures/mock/stream.ndjson         # ~40 SSE frames to replay locally without a backend
```

The UI reads from `fixtures/mock/` when `?mock=1` is in the URL, and from the API otherwise. **Keep that switch working all night.** It is the backup demo when the backend dies at 04:00, and it is the only reason D can start at hour zero.
