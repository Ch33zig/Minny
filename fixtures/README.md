# Mock fixtures

`fixtures/mock/` is the front end's parachute. With `?mock=1` in the URL the UI reads these files
and nothing else; without it, it calls `/api`. The switch works with no backend running, which is
how the UI got built before the API existed and how the demo survives a backend failure.

Shapes follow [00-CONTRACTS.md](../docs/handoff/00-CONTRACTS.md). Values follow
[GROUND-TRUTH.md](../docs/handoff/GROUND-TRUTH.md) and, wherever possible, the dataset itself.

## Provenance

| File | Where the numbers come from |
|---|---|
| `events.json` | 48 lines read byte-for-byte out of `data/logs.txt`: 168311-168346 (the incident window, contiguous, benign lines included) plus 8326, 72117, 100280, 162048 (dismissed lead D1) and 12, 74, 23759, 32059, 48303, 65551, 72083, 96711 (base rates for D2 and D3). Nothing is retyped. |
| `baselines.json` | Computed over `data/logs.txt` with the same parser regex and the same `ts < 2026-03-01T00:00:00-05:00` cutoff the contract specifies. 157,818 baseline events, 10 users, 25 observed templates. |
| `case_file.json` | Claims are re-derivable counts; every `evidence_lines` entry resolves in `events.json`. |
| `alerts.json` | 9 alerts over signals S1-S6 and S8, timestamped from the real lines they cite. |
| `incidents.json` | The real incident with its 9 alerts, plus one synthetic variant carrying `labels.synthetic: true`. |
| `stream.ndjson` | 62 SSE frames generated from the three files above. Monotonic `seq`, types `event`/`alert`/`incident`/`replay_state`/`heartbeat`. The incident is re-emitted six times, each time larger, which is what makes the monitor card grow. |
| `metrics.json` | The real output of `python eval.py --seed 42`, copied byte for byte from `data/metrics.json`. The `placeholder` flag is gone, so the UI no longer prints the warning ribbon: every figure on that panel is now a measured one. Refresh it whenever the evaluation is re-run. |
| `blue_proposals.json` | One accepted rule (R003, slow credential guessing) and one rejected (R004, the `csrf` matcher). Gate numbers are placeholders and flagged as such. |
| `email_evidence.json` | The real output of `python -m minny.integrations.gmail_evidence`, which runs the three bounded queries against the seeded demonstration mailbox in `fixtures/integrations/gmail_mailbox.json`. The mailbox holds six messages; the queries fetch five, because the parking notice is from a sender nobody allowlisted. The file says `seeded_demo_mailbox` and the UI repeats it on screen. |
| `integrations_status.json` | The real output of `GET /api/integrations/status` with no credentials present, which is the state the demo runs in: four capabilities, all of them on recorded responses. |

## Verified facts these fixtures rest on

Each of these was computed against `data/logs.txt`, not taken from a brief.

- 10 users, 10 IPs, one binding violation: `sarah_j` on `10.0.8.45`, which is `david_m`'s.
- Status 400 and status 500 occur exactly once each in 180,800 lines. Both are david_m, lines 168330 and 168331.
- `/api/admin/role_update` and `/assets/avatar_{id}.png` occur exactly once each, lines 168336 and 168337, both in March, neither in the baseline window.
- `david_m` has 80 responses of 403 on the Q1 zip and exactly 1 of 200. `sarah_j` has 1,528 and `nicole_h` 1,532.
- Exactly two clusters of 4 or more 401s inside 10 minutes exist in the whole file. Both are `sarah_j` from `10.0.8.45`. Her tightest gap between failures in the baseline is 809 seconds; inside those bursts it is 2.
- 5,324 responses of 403 overall, 506 to 545 per user. 899 responses of 401 overall, 70 to 102 per user. Denials and failures are near-uniform background here, which is why neither is a signal on its own.
- 5 reads of the Q1 zip fall outside 08:00-18:59. Four are authorized readers on their own IPs; the fifth is line 168345, the theft. Hour of day does not separate them, so nothing in the UI or the detector reads it.

## Known deltas from the contract examples

The contract's JSON blocks were written before the dataset was queried. Where an example
disagrees with the data, the fixture follows the data:

1. **Dismissed lead line number.** Section 7 cites line 161204 for the off-hours access. That line is `ashley_k` fetching `/assets/app.js`. The 00:19 read of the Q1 zip on 6 March is line **162048**.
2. **Off-hours framing.** Section 7 calls after-midnight downloads of the zip "routine". There is exactly one, plus three more outside business hours. The fixture says four, and names them.
3. **Role-update time.** Section 7's F7 puts the role update at 14:13; the data puts it at **11:07:57** on 15 March, line 168336. The seeded email follows the data.
4. **sarah_j's `allowed_paths`.** Section 4's example lists `/api/admin/role_update`. It never appears before March, so it cannot be in a baseline fitted below the cutoff. It is in `privileged_templates` with a `template_freq` of 0, exactly as the section 4 example's `global` block shows.
5. **S7 emits no alert.** Section 5 says so explicitly, so `alerts.json` carries no S7 row even though S7 is listed as a signal. S7 appears where the contract puts it, in `incident.attacker.basis`. The wave brief asking for "one per signal S1-S8" is satisfied with 9 alerts over the 7 signals that emit.
6. **The `csrf` rule is not expressible in the section 10 grammar.** `field` is `user | ip | ip_owner | template | obj_id | status | signal`, with no query or parameter field and no substring operator, so `query CONTAINS "csrf"` cannot parse. The fixture keeps the rule and records the problem in `parse.grammar_note`. C decides: extend the grammar, or the rejected-rule demo becomes a parse rejection instead of a gate rejection.
