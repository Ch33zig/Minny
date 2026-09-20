// Blue agent. A rejected rule sits next to an accepted one on purpose: the rule
// that catches the original perfectly and dies on the held-out set is the more
// honest story, and it is the one a judge remembers.

import { api } from '../api.js';
import { esc, fmtPct, fmtTs, noneTag } from '../dom.js';

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
      <section class="panel blue-intro">
        <p class="section-label">PROPOSED DETECTION RULES</p>
        <p>The red team finds an evasion, the blue agent writes a rule against it, and the rule only ships if it clears a gate on data it has never seen. Both outcomes are shown, because a rule that passes the gate and a rule that cannot are equally informative.</p>
        <div class="blue-counts meta">
          <span class="check pass">${accepted.length} accepted</span>
          <span class="check fail">${rejected.length} rejected</span>
        </div>
      </section>

      <section class="panel col rule-col">
        <div class="col-head"><p class="section-label">ACCEPTED</p><span class="col-count meta">${accepted.length}</span></div>
        <div class="col-body">${accepted.map(rule).join('') || '<div class="empty">Nothing has cleared the gate.</div>'}</div>
      </section>

      <section class="panel col rule-col">
        <div class="col-head"><p class="section-label">REJECTED</p><span class="col-count meta">${rejected.length}</span></div>
        <div class="col-body">${rejected.map(rule).join('') || '<div class="empty">Nothing was rejected.</div>'}</div>
      </section>
    </div>`;
}

function rule(r) {
  const gate = r.gate || {};
  const parse = r.parse || {};
  const passed = gate.accepted;
  const checks = Object.entries(gate)
    .filter(([, v]) => v && typeof v === 'object')
    .map(([key, v]) => gateRow(key, v))
    .join('');

  return `
    <article class="card rule ${passed ? 'rule-pass' : 'rule-fail'}">
      <div class="card-head">
        <span class="card-id meta">${esc(r.id || '')}</span>
        <div class="variant-tags">
          ${r.placeholder ? '<span class="op-chip meta none">fixture</span>' : ''}
          <span class="${passed ? 'check pass' : 'check fail'} meta">${passed ? 'ACCEPTED' : 'REJECTED'}</span>
        </div>
      </div>
      <p class="claim">${esc(r.name || '')}</p>
      <div class="rule-meta meta">
        <span>proposed by ${esc(r.proposed_by || 'blue_agent')}</span>
        <span>evades ${esc(r.evaded_family || '?')} ${esc(r.evaded_family_name || '')}</span>
        ${(r.evaded_operators || []).map((o) => `<span class="op-chip">${esc(o)}</span>`).join('')}
      </div>
      ${r.rationale ? `<p class="method"><span class="method-label meta">WHY THIS RULE</span>${esc(r.rationale)}</p>` : ''}

      <div class="dsl">
        <div class="dsl-head meta"><span>WHEN</span>${parse.ok === false ? '<span class="check fail">parse error</span>' : '<span class="meta dsl-ok">parses · depth ' + esc(parse.depth ?? '?') + ' · ' + esc(parse.nodes ?? '?') + ' nodes</span>'}</div>
        <code>${esc(r.when || '')}</code>
        ${r.explain ? `<div class="dsl-explain meta">${esc(r.explain)}</div>` : ''}
        ${parse.error ? `<div class="dsl-error meta">${esc(parse.error)}</div>` : ''}
        ${parse.grammar_note ? `<div class="dsl-note meta">${esc(parse.grammar_note)}</div>` : ''}
      </div>

      <div class="gate">${checks}</div>
      ${gate.rejected_reason ? `<p class="reject-reason">${esc(gate.rejected_reason)}</p>` : ''}
      ${beforeAfter(r.before_after)}
      <div class="inc-foot meta">
        <span>${r.created_ts ? esc(fmtTs(r.created_ts, { withYear: true })) : 'no timestamp'}</span>
        <span>${r.pull_request ? esc(r.pull_request) : 'no pull request opened'}</span>
      </div>
    </article>`;
}

function gateRow(key, v) {
  const target = v.threshold !== undefined ? `threshold ${v.threshold}`
    : v.budget !== undefined ? `budget ${v.budget}`
    : v.required !== undefined ? `required ${v.required}` : '';
  const measured = v.measured !== undefined
    ? esc(v.threshold !== undefined ? fmtPct(v.measured) : String(v.measured))
    : noneTag;
  return `
    <div class="gate-row ${v.pass ? 'pass' : 'fail'}">
      <span class="gate-mark meta">${v.pass ? '✓' : '✕'}</span>
      <span class="gate-name">${esc(GATE_LABEL[key] || key)}</span>
      <span class="gate-target meta">${esc(target)}</span>
      <span class="gate-measured meta">${measured}</span>
    </div>`;
}

function beforeAfter(ba) {
  if (!ba) return '';
  const rows = Object.entries(ba).map(([key, v]) => {
    const pct = key.includes('detection');
    const before = pct ? fmtPct(v.before) : String(v.before);
    const after = pct ? fmtPct(v.after) : String(v.after);
    const moved = v.after !== v.before;
    return `<div class="ba-row">
      <span class="ba-name meta">${esc(key.replace(/_/g, ' '))}</span>
      <span class="ba-val meta">${esc(before)}</span>
      <span class="ba-arrow meta">→</span>
      <span class="ba-val meta ${moved ? 'moved' : 'flat'}">${esc(after)}</span>
    </div>`;
  }).join('');
  return `<div class="ba"><div class="ba-head meta">BEFORE → AFTER</div>${rows}</div>`;
}
