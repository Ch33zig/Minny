// Claim -> raw bytes. This is the interaction the whole product rests on:
// the difference between a tool that asserts and a tool that proves.
//
// Usage:  container.innerHTML = evidenceToggle({ lines, emails });
//         mountEvidence(container);

import { api, resolveLines } from './api.js';
import { esc, fmtTs } from './dom.js';
import { collapseEvidence, expandEvidence, resizeEvidence } from './motion.js';

let uid = 0;

export function evidenceToggle({ lines = [], emails = [], label = null, open = false }) {
  const ids = lines.filter((n) => Number.isFinite(n));
  if (!ids.length && !emails.length) return '';
  const key = `ev${(uid += 1)}`;
  const range = ids.length
    ? (ids.length === 1 ? `line ${ids[0]}` : `${ids.length} lines`)
    : 'mailbox only';
  const title = ids.length ? `lines ${ids.join(', ')}` : 'mailbox records only';
  return `
    <div class="ev" data-ev="${key}">
      <button class="ev-toggle" type="button" data-lines="${esc(ids.join(','))}" data-emails="${esc(emails.join(','))}" aria-expanded="${open ? 'true' : 'false'}" title="${esc(title)}">
        <span class="ev-caret">▸</span>
        <span class="ev-label">${esc(label || 'Show evidence')}</span>
        <span class="ev-count meta">${esc(range)}</span>
        ${emails.length ? `<span class="ev-mail-count meta">+${emails.length} mail</span>` : ''}
      </button>
      <div class="ev-body" hidden></div>
    </div>`;
}

export function mountEvidence(root) {
  if (!root || root.dataset.evMounted === '1') return;
  root.dataset.evMounted = '1';
  root.addEventListener('click', (event) => {
    const button = event.target.closest('.ev-toggle');
    if (!button || !root.contains(button)) return;
    toggle(button);
  });
}

async function toggle(button) {
  const wrap = button.closest('.ev');
  const body = wrap.querySelector('.ev-body');
  const isOpen = button.getAttribute('aria-expanded') === 'true';
  if (isOpen) {
    button.setAttribute('aria-expanded', 'false');
    await collapseEvidence(body);
    body.hidden = true;
    return;
  }
  button.setAttribute('aria-expanded', 'true');
  body.hidden = false;
  if (body.dataset.loaded === '1') return expandEvidence(body);
  body.innerHTML = '<div class="ev-loading meta">resolving line numbers…</div>';
  expandEvidence(body);
  await load(button, body);
}

async function load(button, body) {
  const fromHeight = body.getBoundingClientRect().height;
  const lines = (button.dataset.lines || '').split(',').filter(Boolean).map(Number);
  const emailIds = (button.dataset.emails || '').split(',').filter(Boolean);
  try {
    const [rows, mail] = await Promise.all([
      lines.length ? resolveLines(lines) : Promise.resolve([]),
      api.emailEvidence(emailIds),
    ]);
    body.innerHTML = renderRows(rows) + renderMail(mail);
    body.dataset.loaded = '1';
    resizeEvidence(body, fromHeight);
  } catch (err) {
    body.innerHTML = `<div class="ev-error meta">could not resolve evidence: ${esc(err.message)}</div>`;
  }
}

/**
 * Mailbox corroboration arrives after the claim it sits under, because the
 * claim never waits on it. When a block is already open, reload it in place;
 * when it is closed, drop the cache so the next open picks the mail up.
 */
export function invalidate(button) {
  const wrap = button.closest('.ev');
  const body = wrap && wrap.querySelector('.ev-body');
  if (!body) return;
  body.dataset.loaded = '';
  if (button.getAttribute('aria-expanded') === 'true') load(button, body);
}

function renderRows(rows) {
  if (!rows.length) return '';
  const body = rows.map((row) => {
    if (row.missing) {
      return `<div class="raw-row missing"><span class="raw-ln">${row.line}</span><span class="raw-bytes">not available in this data source</span></div>`;
    }
    const synth = row.synthetic ? ' synthetic' : '';
    return `<div class="raw-row${synth}"><span class="raw-ln">${row.line}</span><span class="raw-bytes">${esc(row.raw)}</span>${row.synthetic ? '<span class="raw-synth meta">INJECTED</span>' : ''}</div>`;
  }).join('');
  const anySynthetic = rows.some((r) => r.synthetic);
  return `
    <div class="raw-head meta">
      <span>PRIMARY EVIDENCE</span>
      <span>${anySynthetic ? 'injected by the red team, not in logs.txt' : 'data/logs.txt, verbatim'}</span>
    </div>
    <pre class="raw">${body}</pre>`;
}

function renderMail(mail) {
  if (!mail || !mail.length) return '';
  // Every record from the demonstration account carries the flag, so the
  // label survives whichever path resolved it.
  const seeded = mail.seeded === true || mail.some((m) => m.seeded_demo_mailbox === true);
  const items = mail.map((m) => `
    <div class="mail-row">
      <div class="mail-top">
        <span class="mail-cat meta">${esc(m.category || 'other')}</span>
        <span class="mail-ts meta">${esc(fmtTs(m.ts))}</span>
      </div>
      <div class="mail-subject">${esc(m.subject)}</div>
      <div class="mail-meta meta">${esc(m.from)} → ${esc((m.to || []).join(', '))}</div>
      <div class="mail-snippet">${esc(m.snippet)}</div>
      <div class="mail-basis meta">${(m.link_basis || []).map((b) => `<span>${esc(b)}</span>`).join('')}<span class="mail-conf">confidence ${esc(m.confidence)}</span></div>
    </div>`).join('');
  return `
    <div class="mail-strip">
      <div class="mail-head meta">
        <span>CORROBORATING EVIDENCE · MAILBOX</span>
        ${seeded ? '<span class="mail-seeded">SEEDED DEMONSTRATION MAILBOX</span>' : ''}
      </div>
      ${items}
      <div class="mail-cap">Mailbox records corroborate a claim and never carry one alone. Headers are forgeable and DKIM was not verified, so a finding resting on mail only is capped at medium.</div>
    </div>`;
}

export function toggleAll(root, open) {
  root.querySelectorAll('.ev-toggle').forEach((button) => {
    const isOpen = button.getAttribute('aria-expanded') === 'true';
    if (isOpen !== open) toggle(button);
  });
}
