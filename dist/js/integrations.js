// The integrations strip in the rail foot.
//
// Four capabilities, four states, no hue. Border style carries the state, the
// same way confidence does everywhere else in this product: solid is
// connected, dashed is running on recorded fixtures, dotted is broken. Amber
// is spent on high severity and the attacker and is not spent here.
//
// It is display only. Nothing in the strip can be clicked, so nothing in it
// can start a vendor call during a demo.

import { api } from './api.js';
import { $, esc } from './dom.js';

const ORDER = ['slack.post', 'gmail.read', 'gmail.send', 'github.pr'];

// Used only when the status call itself fails, so the strip still names four
// capabilities instead of collapsing to one line that says nothing.
const FALLBACK_SHORT = {
  'slack.post': 'SLACK',
  'gmail.read': 'MAIL IN',
  'gmail.send': 'MAIL OUT',
  'github.pr': 'GITHUB',
};

const STATE_LABEL = {
  connected: 'live',
  mock: 'mock',
  error: 'error',
};

export async function mount() {
  const host = $('#integrations');
  if (!host) return;

  let status;
  try {
    status = await api.integrations();
  } catch (err) {
    // A status endpoint that is not answering is itself a not connected
    // state. It is never a reason for the rail to go missing.
    host.innerHTML = rows(
      ORDER.map((id) => ({ id, short: FALLBACK_SHORT[id], state: 'error', summary: err.message })),
      null,
    );
    return;
  }

  const byId = new Map((status.capabilities || []).map((cap) => [cap.id, cap]));
  const ordered = ORDER.map((id) => byId.get(id)).filter(Boolean);
  host.innerHTML = rows(ordered.length ? ordered : status.capabilities || [], status.mailbox);
}

function rows(capabilities, mailbox) {
  const body = capabilities.map(row).join('');
  const seeded = mailbox && mailbox.seeded_demo_mailbox
    ? `<div class="int-seeded" title="${esc(mailbox.disclosure || '')}">seeded demo mailbox</div>`
    : '';
  return `<p class="section-label">INTEGRATIONS</p>${body}${seeded}`;
}

function row(cap) {
  const state = STATE_LABEL[cap.state] ? cap.state : 'error';
  const parts = [cap.summary || ''];
  if (cap.scope) parts.push(`scope ${cap.scope}`);
  if (cap.tool_slug) parts.push(cap.tool_slug);
  if (state === 'mock' && (cap.missing_env || []).length) {
    parts.push(`recorded responses, missing ${cap.missing_env.join(', ')}`);
  }
  const delivery = cap.last_delivery;
  if (delivery && delivery.message) parts.push(`last attempt: ${delivery.message}`);

  return `
    <div class="int-row int-${esc(state)}" title="${esc(parts.filter(Boolean).join('\n'))}">
      <span>${esc(cap.short || cap.id || '')}</span>
      <b>${esc(STATE_LABEL[state])}</b>
    </div>`;
}
