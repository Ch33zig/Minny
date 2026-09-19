# Track D — front end and integrations

**Owner:** D. **Branch:** `track/d-frontend`. **Milestones:** M7 UI, M8 Composio (Slack out, Gmail both ways).

Everything a judge sees is yours. You are also the only person who can start at full speed at 19:30, because the mock fixtures in [00-CONTRACTS.md](00-CONTRACTS.md) exist precisely so you never wait for anyone.

Your track is over-budget — roughly 13 hours of estimate in a 9.5-hour window — so two decisions are already made for you.

## Two decisions, already made

1. **No React, no Next.js.** Extend the existing `dist/index.html`, `dist/styles.css`, `dist/app.js`. The shell already carries the layout and the visual language. A framework rewrite costs 2 to 3 hours and buys the judge nothing. Split `app.js` into ES modules per view if it gets unwieldy; that is the whole build system.
2. **Mock-first, all night.** Create `fixtures/mock/` in your first commit from the blocks in [00-CONTRACTS.md](00-CONTRACTS.md) section 13. `?mock=1` reads fixtures, otherwise the API. **Keep that switch working until the end** — it is how you start before the backend exists, and it is the backup demo when something dies at 04:00.

## Checklist

- [ ] **20:15** `fixtures/mock/` committed; `?mock=1` switch working
- [ ] **21:30** Case-file view rendering from mock `case_file.json`, claims expanding to raw lines
- [ ] **23:00** Live monitor with replay controls, ticker, incident cards, all from `stream.ndjson` — **C3**
- [ ] **00:00** Switch case file and monitor to the real API; report mismatches to A and B immediately
- [ ] **01:00** Judge panel wired to `POST /api/redteam/generate` — **C4**
- [ ] **02:00** Metrics panel and blue-agent panel from real JSON
- [ ] **03:00** M8: Slack alert fires; Gmail evidence sync returns real messages — **C5**
- [ ] **04:00** GitHub PR on accepted rule, or cut
- [ ] **05:00** Freeze, mock path re-verified end to end

## M7 — the UI (start now, finish by 03:00)

Build in this order. Each view is demo-ready on its own, so if you run out of time you run out at the back.

### 1. Case file — "Log & Order" styling

Suspect cards for attacker and victim, the timeline, the verdict with its confidence label, unknowns, dismissed leads. **Every claim expands to raw log lines by line number** via `GET /api/events?lines=`. That expansion is the single most important interaction in the product: it is the difference between an AI that asserts and a tool that proves. Make it fast, make it obviously clickable, and make sure the raw text is the file's bytes and not something re-rendered.

Render `confidence` as a visible label everywhere it appears. The heuristic post-attribution finding must *look* different from the IP-binding finding, because one of them is inference and the other is arithmetic.

Dismissed leads get equal visual weight to findings. "We checked the late-night access and it was nothing" is a claim about rigour, and it is 10 seconds of the demo.

### 2. Live monitor

Replay controls with speed, an event ticker, and incident cards that **grow as correlated alerts arrive**. The growth is the whole effect: an analyst reading one story instead of twenty warnings. Do not render alerts as a flat list and call it done.

Each card shows the plain-English explanation from the incident object and drills down to evidence. A synthetic incident (`labels.synthetic: true`) carries a visible badge — nobody on stage should ever be unsure whether they are looking at the real breach or an injected variant.

Consume SSE per section 12. Handle reconnect using `seq` to detect a gap, and treat `heartbeat` as a no-op. Assume the stream will drop at least once during the demo.

### 3. Judge's panel

Pick attacker, victim, target file, and up to two operators; `POST /api/redteam/generate`; the variant is injected into the running replay and the incident appears. **Up to two operators** — the plan's own cut list says operators beyond two go first, so do not build a combinatorial form.

Populate the dropdowns from `access_matrix.json` so a judge cannot construct an incoherent attack and get a confusing result.

### 4. Metrics panel

Straight from `metrics.json`: detection by operator, false positives per day, time to detect. The per-operator table is the most interesting thing on screen — give it room. Never hardcode a number; if C regenerates at 04:00, this panel changes by itself.

### 5. Blue-agent panel

The evaded family, the proposed rule, gate results pass/fail per check, before/after numbers. **Show a rejected rule alongside an accepted one.** The `csrf` rule that catches the original perfectly and fails the held-out gate is a better story than any acceptance.

### Delete the fake behavior

`dist/app.js` currently contains scripted detections, hardcoded PR numbers, timers, and coverage increments from the earlier demo. All of it goes. A judge who spots a fabricated PR number has stopped believing everything else on the screen.

## M8 — integrations (target 03:00, after M7 works)

Reference: [04-COMPOSIO.md](../technical-spec/04-COMPOSIO.md) for setup, exact tool slugs, webhook handling, and idempotency. Note that **nothing is provisioned** — no Composio project, Slack workspace, or GitHub repo was found. Budget the OAuth round trip.

**Every integration fails soft.** No connection, expired token, rate limit, or vendor outage may change the case file, the detector, the incidents, or the metrics. Nothing on the critical path `await`s a vendor. The demo continues with a "not connected" chip and nobody notices.

### Slack, outbound — keep this one

On a high-severity incident, post the plain-English explanation plus a link to the incident. `SLACK_CHAT_POST_MESSAGE`, and `SLACK_RETRIEVE_MESSAGE_PERMALINK_URL` if you want the link back. **Never post raw log lines or email content to Slack** — post the Minny link.

### Gmail, inbound as evidence — the new one

This is the addition that makes the case file better rather than louder. Logs answer *what happened*; they are silent on *who authorized it*. A permission-change notification names the grantee the log never records. An access-request approval, a group or cluster membership change, a credential reset, a data-export confirmation — each can close one of A's open unknowns. U1 (how the login as sarah_j succeeded) and U3 (who revoked david_m's access) are exactly that shape.

Implement to [00-CONTRACTS.md](00-CONTRACTS.md) section 11, and read that section before writing a line — the linking rules, the confidence cap, and the privacy constraints are all load-bearing:

- **Read-only scope**, separate from the send scope. Show them as two independent capabilities in the UI, because a user granting one has not granted the other.
- **Bounded, app-coded queries only.** A fixed window, a sender allowlist, a subject keyword set. Never a free-text query assembled from LLM output. Never a full mailbox crawl.
- **Store headers, category, matched entities, and snippet. Never bodies.** Nothing from the mailbox leaves the app — not into a GitHub issue, not into a PR body, not into Slack. They carry a Minny evidence link instead, which matches the existing rule in [04-COMPOSIO.md](../technical-spec/04-COMPOSIO.md) section 7.
- **Classify deterministically first** from a keyword and sender map. An LLM may refine `other`; it may never invent a `matched_entity`.
- **Link on entity match AND time proximity**, both required, with `link_basis` recorded so the UI can show why a message is attached. Time alone is not evidence.
- **Cap the confidence.** A claim resting on email alone is `medium` and renders as *"supported by mailbox records only"*. Mail headers are forgeable and we did not verify DKIM. Say it before a judge does.

Write `data/email_evidence.json`, expose `GET /api/evidence/email?ids=`, and tell B when the file exists so the correlator can attach `evidence_emails`. In the UI, email corroboration is a separate strip under a finding, visually distinct from log evidence — the distinction between primary and corroborating evidence should be visible, not just documented.

**Seed the demo mailbox** with 5 or 6 messages matching the story timeline: the role-update notification at 14:13 on 27 March, an access request, a revocation, a data-export confirmation, and two unrelated messages so the entity matcher has something to correctly ignore. **Label it a seeded demonstration mailbox in the UI and in the Devpost.** There is no real corporate mailbox for this dataset, and a judge discovering that unprompted costs more than saying it first.

### GitHub PR — cut before Slack

On an accepted rule, open a PR to a rules repo; the body carries the evaded variant, gate results, and FP numbers. Merge stays manual and the judge can click it. Per [04-COMPOSIO.md](../technical-spec/04-COMPOSIO.md) section 7: use "Related to #N", never "Closes #N", and never force-push over a human's commit.

### Out of scope tonight

Sentry and the ES|QL translation are cut — the top two entries in the plan's own cut order, and the sponsor-lock deadline has already passed, so confirm at kickoff what was actually submitted. If Sentry was locked in, it is your **last** task after everything above, following [05-FRONTEND-AND-SENTRY.md](../technical-spec/05-FRONTEND-AND-SENTRY.md) section 4, and it is never a prerequisite for anything else.

## Done when

The full demo runs from the UI with no terminal, in both `?mock=1` and live modes. Test the mock path last, at 05:00, after everything else is frozen. It is the parachute.
