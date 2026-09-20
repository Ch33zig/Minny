// Claim -> raw bytes. This is the interaction the whole board rests on: the
// difference between a card that asserts and a card that proves.
//
// It is also where the board keeps its text. A card carries one short claim;
// the paragraph behind it travels in `detail` and only unfolds when someone
// pulls the clip.
//
// Usage:  container.innerHTML = evidenceToggle({ lines, emails, detail });
//         mountEvidence(container);

import { api, resolveLines } from './api.js';
import { esc, fmtTs } from './dom.js';
import { collapseEvidence, expandEvidence, resizeEvidence } from './motion.js';

let uid = 0;

const CLIP = `<svg class="clip-icon" width="11" height="16" viewBox="0 0 11 16" aria-hidden="true">
  <path d="M8.4 4.2v7.2a3.4 3.4 0 0 1-6.8 0V3.6A2.2 2.2 0 0 1 6 3.6v7.6a1 1 0 0 1-2 0V4.4"
        fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
</svg>`;

export function evidenceToggle({ lines = [], emails = [], label = null, open = false, detail = '' }) {
  const ids = lines.filter((n) => Number.isFinite(n));
  if (!ids.length && !emails.length && !detail) return '';
  const key = `ev${(uid += 1)}`;
  const range = ids.length
    ? (ids.length === 1 ? `line ${ids[0]}` : `${ids.length} lines`)
    : (emails.length ? 'mailbox only' : 'no lines cited');
  const title = ids.length ? `lines ${ids.join(', ')}` : 'mailbox records only';
  return `
    <div class="ev" data-ev="${key}">
      <button class="ev-toggle" type="button" data-lines="${esc(ids.join(','))}" data-emails="${esc(emails.join(','))}" aria-expanded="${open ? 'true' : 'false'}" title="${esc(title)}">
        ${CLIP}
        <span class="ev-label">${esc(label || 'Pull the evidence')}</span>
        <span class="ev-count">${esc(range)}</span>
        ${emails.length ? `<span class="ev-mail-count">+${emails.length} mail</span>` : ''}
      </button>
      <div class="ev-body" hidden>${detail ? `<div class="ev-detail">${detail}</div>` : ''}</div>
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
  bound(body);
  if (body.dataset.loaded === '1') return expandEvidence(body);
  const lines = (button.dataset.lines || '').split(',').filter(Boolean).map(Number);
  const emailIds = (button.dataset.emails || '').split(',').filter(Boolean);
  if (!lines.length && !emailIds.length) {
    body.dataset.loaded = '1';
    return expandEvidence(body);
  }
  const slot = document.createElement('div');
  slot.className = 'ev-loading';
  slot.textContent = 'resolving line numbers…';
  body.appendChild(slot);
  expandEvidence(body);
  const fromHeight = body.getBoundingClientRect().height;
  try {
    const [rows, mail] = await Promise.all([
      lines.length ? resolveLines(lines) : Promise.resolve([]),
      api.emailEvidence(emailIds),
    ]);
    slot.outerHTML = renderRows(rows) + renderMail(mail);
    body.dataset.loaded = '1';
    resizeEvidence(body, fromHeight);
  } catch (err) {
    slot.className = 'ev-error';
    slot.textContent = `could not resolve evidence: ${err.message}`;
  }
}


/**
 * On a sheet the slip hangs off the card instead of growing it, so it has to
 * be told how much room it has and which way to unfold. Off a sheet this does
 * nothing and the block opens the way it always did.
 */
function bound(body) {
  const sheet = body.closest('.sheet');
  if (!sheet) return;
  const box = body.parentElement.getBoundingClientRect();
  const area = sheet.getBoundingClientRect();
  const below = area.bottom - box.bottom - 12;
  const above = box.top - area.top - 12;
  const up = below < 170 && above > below;
  body.classList.toggle('up', up);
  body.style.setProperty('--ev-max', `${Math.max(130, Math.round(up ? above : below))}px`);
}

/* The photocopy: the flattest, cleanest paper on the board. No grain sits
   behind raw log bytes, because that block is the proof. */
function renderRows(rows) {
  if (!rows.length) return '';
  const body = rows.map((row) => {
    if (row.missing) {
      return `<div class="raw-row missing"><span class="raw-ln">${row.line}</span><span class="raw-bytes">not available in this data source</span></div>`;
    }
    const synth = row.synthetic ? ' synthetic' : '';
    return `<div class="raw-row${synth}"><span class="raw-ln">${row.line}</span><span class="raw-bytes">${esc(row.raw)}</span>${row.synthetic ? '<span class="raw-synth">INJECTED</span>' : ''}</div>`;
  }).join('');
  const anySynthetic = rows.some((r) => r.synthetic);
  return `
    <div class="photocopy">
      <div class="raw-head">
        <span class="tw">Primary evidence</span>
        <span class="meta">${anySynthetic ? 'injected by the red team, not in logs.txt' : 'data/logs.txt, verbatim'}</span>
      </div>
      <pre class="raw">${body}</pre>
    </div>`;
}

/* Mailbox records are visibly a different document: a smaller slip, taped on
   at an angle. They corroborate and never carry a claim alone. */
function renderMail(mail) {
  if (!mail || !mail.length) return '';
  const seeded = mail.seeded !== false;
  const items = mail.map((m) => `
    <div class="mail-row">
      <div class="mail-top">
        <span class="tw">${esc(m.category || 'other')}</span>
        <span class="meta">${esc(fmtTs(m.ts))}</span>
      </div>
      <div class="mail-subject">${esc(m.subject)}</div>
      <div class="mail-meta meta">${esc(m.from)} to ${esc((m.to || []).join(', '))}</div>
      <div class="mail-snippet">${esc(m.snippet)}</div>
      <div class="mail-basis meta">${(m.link_basis || []).map((b) => `<span>${esc(b)}</span>`).join('')}<span class="mail-conf">confidence ${esc(m.confidence)}</span></div>
    </div>`).join('');
  return `
    <div class="mail-strip">
      <span class="tape top"></span>
      <div class="mail-head">
        <span class="tw">Corroborating · mailbox</span>
        ${seeded ? '<span class="stamp pencil-stamp">SEEDED</span>' : ''}
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
