import { api } from '../api.js';
import { confChip, esc, fmtTs, NONE, noneTag } from '../dom.js';
import { evidenceToggle, invalidate, mountEvidence, toggleAll } from '../evidence.js';

export async function render(container) {
  const cf = await api.caseFile();
  const a = (cf.actors && cf.actors.attacker) || {};
  const v = (cf.actors && cf.actors.victim) || {};

  container.innerHTML = `
    <div class="case-grid">
      ${verdict(cf)}
      <section class="panel col" id="actorsCol">
        <div class="col-head">
          <p class="section-label">SUSPECTS</p>
          <span class="col-count meta">2</span>
        </div>
        <div class="col-body">
          ${suspect(a, 'attacker')}
          ${suspect(v, 'victim')}
          <div class="col-head inner">
            <p class="section-label">OPEN UNKNOWNS</p>
            <span class="col-count meta">${(cf.unknowns || []).length}</span>
          </div>
          ${(cf.unknowns || []).map(unknown).join('') || empty('Nothing left open.')}
        </div>
      </section>

      <section class="panel col" id="findingsCol">
        <div class="col-head">
          <p class="section-label">FINDINGS</p>
          <span class="col-count meta">${(cf.findings || []).length}</span>
        </div>
        <div class="col-body">${(cf.findings || []).map(finding).join('') || empty('No findings in this case file.')}</div>
      </section>

      <section class="panel col" id="timelineCol">
        <div class="col-head">
          <p class="section-label">TIMELINE</p>
          <span class="col-count meta">${(cf.timeline || []).length}</span>
        </div>
        <div class="col-body">${(cf.timeline || []).map(beat).join('') || empty('No timeline recorded.')}</div>
      </section>

      <section class="panel col" id="sideCol">
        <div class="col-head">
          <p class="section-label">DISMISSED LEADS</p>
          <span class="col-count meta">${(cf.dismissed || []).length}</span>
        </div>
        <div class="col-body">
          <p class="col-intro">Leads that were checked and closed. A case is only as good as what it ruled out.</p>
          ${(cf.dismissed || []).map(dismissed).join('') || empty('Nothing was ruled out.')}
        </div>
      </section>
    </div>`;

  mountEvidence(container);

  // ?open=1 opens every evidence block on load, for a walkthrough that starts
  // with the proof already on screen rather than a click away.
  if (new URLSearchParams(location.search).get('open') === '1') toggleAll(container, true);

  // Deliberately not awaited. Mailbox records corroborate a claim and never
  // carry one, so the case file renders first and the corroboration attaches
  // when it arrives, or never, and the page is correct either way.
  attachCorroboration(container, cf);
}

/**
 * Hang mailbox records under the findings whose log lines they are pinned to.
 *
 * The linking already happened during the Gmail sync and is recorded in
 * `linked_lines`, so nothing here re-decides what attaches to what. A case
 * file that already names its `evidence_emails` keeps them and gains any
 * others that match.
 */
async function attachCorroboration(container, cf) {
  const findings = cf.findings || [];
  const lines = findings.flatMap((f) => f.evidence_lines || []);
  let mail = [];
  try {
    mail = await api.emailEvidenceByLines(lines);
  } catch (err) {
    return;
  }
  if (!mail.length) return;

  for (const f of findings) {
    const own = new Set(f.evidence_lines || []);
    const ids = new Set(f.evidence_emails || []);
    for (const m of mail) {
      if ((m.linked_lines || []).some((n) => own.has(n))) ids.add(m.evidence_id);
    }
    if (!ids.size) continue;

    const card = container.querySelector(`[data-finding="${CSS.escape(f.id)}"]`);
    const button = card && card.querySelector('.ev-toggle');
    if (!button) continue;
    const next = Array.from(ids).join(',');
    if (button.dataset.emails === next) continue;
    button.dataset.emails = next;

    let badge = button.querySelector('.ev-mail-count');
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'ev-mail-count meta';
      button.appendChild(badge);
    }
    badge.textContent = `+${ids.size} mail`;
    invalidate(button);
  }
}

function empty(text) {
  return `<div class="empty">${esc(text)}</div>`;
}

function verdict(cf) {
  const vd = cf.verdict || {};
  const actors = cf.actors || {};
  return `
    <section class="panel verdict">
      <div class="verdict-head">
        <h2 class="verdict-headline">Verdict</h2>
        ${confChip(vd.confidence)}
      </div>
      <p class="verdict-text">${esc(vd.summary || 'No verdict recorded.')}</p>
      ${vd.basis ? `<p class="verdict-basis">${esc(vd.basis)}</p>` : ''}
      <div class="verdict-facts">
        <div><span>ATTACKER</span><b>${esc((actors.attacker || {}).user) || noneTag}</b></div>
        <div><span>VICTIM ACCOUNT</span><b>${esc((actors.victim || {}).user) || noneTag}</b></div>
        <div class="wide"><span>ASSET</span><b class="meta">${esc(actors.asset) || noneTag}</b></div>
        <div><span>VECTOR</span><b class="meta">${esc(vectorLabel(actors.vector))}</b></div>
      </div>
    </section>`;
}

function vectorLabel(vector) {
  if (!vector) return NONE;
  const t = vector.template || '';
  if (vector.obj_id === null || vector.obj_id === undefined) return t || NONE;
  return t.includes('{id}') ? t.replace('{id}', vector.obj_id) : `${t} · ${vector.obj_id}`;
}

function initials(user) {
  if (!user) return '??';
  const parts = String(user).split('_');
  return ((parts[0] || '')[0] || '?').toUpperCase() + ((parts[1] || parts[0] || '')[0] || '').toUpperCase();
}

function suspect(actor, kind) {
  if (!actor || !actor.user) return '';
  const stats = (actor.stats || []).map((s) =>
    `<div class="stat"><b class="meta">${esc(s.value)}</b><span>${esc(s.label)}</span></div>`).join('');
  return `
    <article class="suspect ${esc(kind)}">
      <div class="suspect-head">
        <div class="suspect-face">${esc(initials(actor.user))}</div>
        <div class="suspect-id">
          <div class="suspect-name">${esc(actor.user)}</div>
          <div class="suspect-ip meta">${esc(actor.ip || 'no IP recorded')}</div>
        </div>
        <div class="suspect-tags">
          <span class="role role-${esc(kind)}">${esc(kind)}</span>
          ${confChip(actor.confidence)}
        </div>
      </div>
      ${actor.summary ? `<p class="suspect-sum">${esc(actor.summary)}</p>` : ''}
      ${stats ? `<div class="suspect-stats">${stats}</div>` : ''}
      ${evidenceToggle({ lines: actor.evidence_lines || [], label: 'Card evidence' })}
    </article>`;
}

function finding(f) {
  const level = (f.confidence || 'low').toLowerCase();
  const mailOnly = (!f.evidence_lines || !f.evidence_lines.length) && (f.evidence_emails || []).length;
  return `
    <article class="card finding conf-edge-${esc(level)}" data-finding="${esc(f.id || '')}">
      <div class="card-head">
        <span class="card-id meta">${esc(f.id || '')}</span>
        ${confChip(f.confidence)}
      </div>
      <p class="claim">${esc(f.claim)}</p>
      ${mailOnly ? '<p class="mail-only">Supported by mailbox records only.</p>' : ''}
      <p class="method"><span class="method-label meta">METHOD</span>${esc(f.method || '')}</p>
      ${f.query ? `<div class="query meta" title="A saved, re-runnable query in the forensics module">${esc(f.query)}</div>` : ''}
      ${evidenceToggle({ lines: f.evidence_lines || [], emails: f.evidence_emails || [] })}
    </article>`;
}

function beat(t) {
  const level = (t.confidence || 'high').toLowerCase();
  const lines = t.evidence_lines && t.evidence_lines.length ? t.evidence_lines : (t.line ? [t.line] : []);
  return `
    <article class="beat conf-edge-${esc(level)}">
      <div class="beat-head">
        <span class="beat-ts meta">${esc(fmtTs(t.ts))}</span>
        <span class="beat-actor">${esc(t.actor) || noneTag}</span>
        ${level === 'high' ? '' : confChip(t.confidence)}
      </div>
      <p class="beat-action">${esc(t.action || '')}</p>
      ${t.note ? `<p class="beat-note">${esc(t.note)}</p>` : ''}
      ${evidenceToggle({ lines, label: 'Raw' })}
    </article>`;
}

function dismissed(d) {
  return `
    <article class="card dismissed">
      <div class="card-head">
        <span class="card-id meta">${esc(d.id || '')}</span>
        <span class="cleared">CLEARED</span>
      </div>
      <p class="claim">${esc(d.lead)}</p>
      <p class="method"><span class="method-label meta">WHY IT IS NOTHING</span>${esc(d.why || '')}</p>
      ${d.query ? `<div class="query meta">${esc(d.query)}</div>` : ''}
      ${evidenceToggle({ lines: d.evidence_lines || [], label: 'Show what we checked' })}
    </article>`;
}

function unknown(u) {
  return `
    <article class="card unknown">
      <div class="card-head">
        <span class="card-id meta">${esc(u.id || '')}</span>
        ${u.closed_by ? '<span class="closed">CORROBORATED BY MAILBOX</span>' : '<span class="open-tag">OPEN</span>'}
      </div>
      <p class="claim small">${esc(u.text)}</p>
      ${u.closed_by ? evidenceToggle({ emails: [u.closed_by], label: 'Mailbox record' }) : ''}
    </article>`;
}
