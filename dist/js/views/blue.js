// Blue agent. Two memos face each other: a rejected rule sits next to an
// accepted one on purpose. The rule that catches the original perfectly and
// dies on the held-out set is the more honest story, and it is the one a judge
// remembers.

import { api } from '../api.js';
import { esc, fmtPct, fmtTs, noneTag } from '../dom.js';
import { layStamp } from '../motion.js';

const GATE_LABEL = {
  heldout_detection: 'held-out detection',
  benign_fp_delta: 'benign false-positive delta',
  baseline_window_hits: 'baseline window hits',
};

export async function render(container) {
  const proposals = await api.blueProposals();
  const accepted = proposals.filter((p) => p.status === 'accepted' || (p.gate || {}).accepted);
  const rejected = proposals.filter((p) => !(p.status === 'accepted' || (p.gate || {}).accepted));

  container.innerHTML = `
    <div class="blue-grid">
      <section class="blue-note">
        <span class="pin"></span>
        <h2 class="tw">Proposed detection rules</h2>
        <p class="blue-lede">A rule ships only if it clears a gate on data it has never seen.</p>
        <p class="hand aside">both outcomes are pinned up, because a rule that cannot pass is just as informative</p>
      </section>

      <div class="memo-row">
        ${accepted.map((r) => memo(r, true)).join('') || '<div class="empty">Nothing has cleared the gate.</div>'}
        ${rejected.map((r) => memo(r, false)).join('') || '<div class="empty">Nothing was rejected.</div>'}
      </div>
    </div>`;

  // The gate result is a verdict, so its stamp lands once.
  container.querySelectorAll('.memo-stamp').forEach(layStamp);
}

function memo(r, passed) {
  const gate = r.gate || {};
  const parse = r.parse || {};
  const checks = Object.entries(gate)
    .filter(([, v]) => v && typeof v === 'object')
    .map(([key, v]) => gateRow(key, v))
    .join('');

  return `
    <article class="memo ${passed ? 'memo-pass' : 'memo-fail'}" style="--rot:${rot(r.id || r.name)}">
      <span class="pin ${passed ? '' : 'red'} left"></span><span class="pin ${passed ? '' : 'red'} right"></span>
      <span class="stamp big memo-stamp ${passed ? 'ink' : ''}">${passed ? 'ACCEPTED' : 'REJECTED'}</span>
      <div class="memo-head">
        <span class="tw">Memorandum</span>
        <span class="card-id">${esc(r.id || '')}</span>
      </div>
      <h3 class="memo-title">${esc(r.name || '')}</h3>
      <div class="memo-from">
        <span class="tw">From</span> ${esc(r.proposed_by || 'blue_agent')}
        <span class="tw">Re</span> ${esc(r.evaded_family || '?')} ${esc(r.evaded_family_name || '')}
        ${(r.evaded_operators || []).map((o) => `<span class="op-chip">${esc(o)}</span>`).join('')}
      </div>

      <div class="dsl">
        <div class="dsl-head">
          <span class="tw">When</span>
          ${parse.ok === false
            ? '<span class="tick-mark fail">parse error</span>'
            : `<span class="dsl-ok">parses, depth ${esc(parse.depth === undefined ? '?' : parse.depth)}, ${esc(parse.nodes === undefined ? '?' : parse.nodes)} nodes</span>`}
        </div>
        <code>${esc(r.when || '')}</code>
        ${r.explain ? `<div class="dsl-explain">${esc(r.explain)}</div>` : ''}
        ${parse.error ? `<div class="dsl-error">${esc(parse.error)}</div>` : ''}
      </div>

      <div class="gate">
        <div class="tw gate-title">Gate</div>
        ${checks}
      </div>
      ${rejectReason(gate.rejected_reason)}
      ${beforeAfter(r.before_after)}
      ${r.rationale ? `<p class="memo-why">${esc(r.rationale)}</p>` : ''}
      <div class="memo-foot">
        <span>${r.created_ts ? esc(fmtTs(r.created_ts, { withYear: true })) : 'no timestamp'}</span>
        <span>${r.pull_request ? esc(r.pull_request) : 'no pull request opened'}</span>
        ${r.placeholder ? '<span class="stamp faint">FIXTURE</span>' : ''}
      </div>
    </article>`;
}

/* A failed check keeps its numbers readable and takes a red pencil through
   the line, the way a reviewer would strike it on paper. */
function gateRow(key, v) {
  const target = v.threshold !== undefined ? `threshold ${v.threshold}`
    : v.budget !== undefined ? `budget ${v.budget}`
    : v.required !== undefined ? `required ${v.required}` : '';
  const measured = v.measured !== undefined
    ? esc(v.threshold !== undefined ? fmtPct(v.measured) : String(v.measured))
    : noneTag;
  return `
    <div class="gate-row ${v.pass ? 'pass' : 'fail'}">
      <span class="gate-mark">${v.pass ? '&#10003;' : '&#10007;'}</span>
      <span class="gate-name">${esc(GATE_LABEL[key] || key)}</span>
      <span class="gate-target">${esc(target)}</span>
      <span class="gate-measured">${measured}</span>
    </div>`;
}

/* The first line of a rejection is the reviewer's own note in the margin.
   What follows is technical, so it stays typed and readable. */
function rejectReason(text) {
  if (!text) return '';
  const s = String(text).trim();
  const m = /^[\s\S]*?[.!?](?=\s|$)/.exec(s);
  const head = m ? m[0] : s;
  const rest = s.slice(head.length).trim();
  return `<p class="hand aside reject-reason">${esc(head)}</p>${rest ? `<p class="memo-note">${esc(rest)}</p>` : ''}`;
}

function beforeAfter(ba) {
  if (!ba) return '';
  const rows = Object.entries(ba).map(([key, v]) => {
    const pct = key.includes('detection');
    const before = pct ? fmtPct(v.before) : String(v.before);
    const after = pct ? fmtPct(v.after) : String(v.after);
    const moved = v.after !== v.before;
    return `<div class="ba-row">
      <span class="ba-name">${esc(key.replace(/_/g, ' '))}</span>
      <span class="ba-val">${esc(before)}</span>
      <span class="ba-arrow">to</span>
      <span class="ba-val ${moved ? 'moved' : 'flat'}">${esc(after)}</span>
    </div>`;
  }).join('');
  return `<div class="ba"><div class="tw">Before and after</div>${rows}</div>`;
}

function rot(seed, max = 0.7) {
  let h = 0;
  const s = String(seed);
  for (let i = 0; i < s.length; i += 1) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return `${((((h % 997) / 997) * 2 - 1) * max).toFixed(2)}deg`;
}
