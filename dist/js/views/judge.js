// Judge's panel. Dropdowns are populated from the fitted baseline, so an
// incoherent attack cannot be constructed in the first place: the victim is
// always someone who can read the target, the attacker always someone who cannot.

import { api, MOCK } from '../api.js';
import { $, esc, toast } from '../dom.js';

const FAMILIES = [
  ['F1', 'credential_takeover'],
  ['F2', 'content_privilege_escalation'],
  ['F3', 'cover_download'],
  ['F4', 'full_chain'],
];
const OPERATORS = [
  'slow_guess', 'own_ip_takeover', 'param_rename', 'victim_swap', 'target_swap',
  'business_hours', 'delay_gap', 'no_cleanup', 'no_cover_download',
];
const MAX_OPERATORS = 2;

let access = { targets: [], authorized: new Map(), denied: new Map() };

export async function render(container) {
  const baselines = await api.baselines();
  buildAccess(baselines);

  container.innerHTML = `
    <div class="judge-grid">
      <section class="panel judge-form">
        <div class="col-head"><p class="section-label">BUILD A VARIANT</p></div>
        <div class="col-body">
          <p class="col-intro">Pick an attack and watch the detector meet it for the first time. Options come from the access model fitted before March, so every combination on offer is one that could really happen.</p>

          <label class="field">
            <span>TARGET FILE</span>
            <select id="jTarget">${access.targets.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join('')}</select>
          </label>
          <label class="field">
            <span>VICTIM — an account authorized to read it</span>
            <select id="jVictim"></select>
          </label>
          <label class="field">
            <span>ATTACKER — an account that is not</span>
            <select id="jAttacker"></select>
          </label>
          <label class="field">
            <span>FAMILY</span>
            <select id="jFamily">${FAMILIES.map(([id, name]) => `<option value="${id}">${id} · ${name}</option>`).join('')}</select>
          </label>

          <div class="field">
            <span>OPERATORS — at most ${MAX_OPERATORS}</span>
            <div class="ops" id="jOps">
              ${OPERATORS.map((o) => `<label class="op"><input type="checkbox" value="${esc(o)}"><span class="mono">${esc(o)}</span></label>`).join('')}
            </div>
          </div>

          <div class="judge-actions">
            <button class="ctl primary-ctl" id="jRun" type="button">Generate and inject</button>
            <span class="mono judge-note" id="jNote"></span>
          </div>
        </div>
      </section>

      <section class="panel col judge-out">
        <div class="col-head"><p class="section-label">VARIANT LABEL</p><span class="col-count mono" id="jCount">0</span></div>
        <div class="col-body" id="jResults"><div class="empty">Nothing generated yet.</div></div>
      </section>
    </div>`;

  const target = $('#jTarget', container);
  target.addEventListener('change', () => fillActors(container));
  fillActors(container);

  const ops = $('#jOps', container);
  ops.addEventListener('change', () => {
    const checked = Array.from(ops.querySelectorAll('input:checked'));
    ops.querySelectorAll('input').forEach((input) => {
      input.disabled = !input.checked && checked.length >= MAX_OPERATORS;
    });
  });

  $('#jRun', container).addEventListener('click', () => generate(container));
}

function buildAccess(baselines) {
  const users = (baselines && baselines.users) || {};
  const authorized = new Map();
  const denied = new Map();
  for (const [user, info] of Object.entries(users)) {
    for (const path of info.allowed_paths || []) {
      if (!authorized.has(path)) authorized.set(path, []);
      authorized.get(path).push(user);
    }
    for (const path of info.denied_paths || []) {
      if (!denied.has(path)) denied.set(path, []);
      denied.get(path).push(user);
    }
  }
  // A usable target is one somebody can read and somebody else cannot.
  const targets = Array.from(authorized.keys())
    .filter((p) => (denied.get(p) || []).length > 0)
    .sort((a, b) => Number(b.includes('CONFIDENTIAL')) - Number(a.includes('CONFIDENTIAL')) || a.localeCompare(b));
  access = { targets, authorized, denied };
}

function fillActors(container) {
  const target = $('#jTarget', container).value;
  const victims = access.authorized.get(target) || [];
  const attackers = access.denied.get(target) || [];
  $('#jVictim', container).innerHTML = victims.map((u) => `<option value="${esc(u)}">${esc(u)}</option>`).join('')
    || '<option value="">no authorized reader in the baseline</option>';
  $('#jAttacker', container).innerHTML = attackers.map((u) => `<option value="${esc(u)}">${esc(u)}</option>`).join('')
    || '<option value="">everyone can read this</option>';
  $('#jNote', container).textContent =
    `${victims.length} authorized · ${attackers.length} denied, fitted before 2026-03-01`;
}

let generated = 0;

async function generate(container) {
  const button = $('#jRun', container);
  const body = {
    target: $('#jTarget', container).value,
    victim: $('#jVictim', container).value,
    attacker: $('#jAttacker', container).value,
    family: $('#jFamily', container).value,
    operators: Array.from($('#jOps', container).querySelectorAll('input:checked')).map((i) => i.value),
  };
  if (!body.victim || !body.attacker) return toast('That target has no coherent attacker/victim pair.', 'bad');
  if (body.attacker === body.victim) return toast('Attacker and victim cannot be the same account.', 'bad');

  button.disabled = true;
  button.textContent = 'Generating…';
  try {
    const variant = await api.redteamGenerate(body);
    generated += 1;
    $('#jCount', container).textContent = String(generated);
    const list = $('#jResults', container);
    const empty = list.querySelector('.empty');
    if (empty) empty.remove();
    list.insertAdjacentHTML('afterbegin', variantCard(variant, body));
    toast(MOCK
      ? 'Variant label built from the baseline. Injection into the replay needs the live API.'
      : 'Variant injected into the running replay.');
  } catch (err) {
    toast(`Generate failed: ${err.message}`, 'bad');
  } finally {
    button.disabled = false;
    button.textContent = 'Generate and inject';
  }
}

function variantCard(v, request) {
  const critic = v.critic || {};
  const checks = (critic.checks_passed || []).map((c) => `<span class="check pass mono">${esc(c)}</span>`).join('');
  const ops = (v.operators || request.operators || []).map((o) => `<span class="op-chip mono">${esc(o)}</span>`).join('')
    || '<span class="op-chip mono none">no operators</span>';
  return `
    <article class="card variant">
      <div class="card-head">
        <span class="card-id mono">${esc(v.variant_id || 'variant')}</span>
        <div class="variant-tags">
          ${v.mock ? '<span class="synth-badge">LABEL ONLY · NO BACKEND</span>' : '<span class="synth-badge">INJECTED</span>'}
          <span class="${critic.accepted ? 'check pass' : 'check fail'} mono">${critic.accepted ? 'critic accepted' : 'critic rejected'}</span>
        </div>
      </div>
      <p class="claim">${esc(v.attacker || request.attacker)} → ${esc(v.victim || request.victim)}</p>
      <div class="query mono">${esc(v.target || request.target)}</div>
      <div class="variant-row mono"><span>FAMILY</span><b>${esc(v.family || request.family)} · ${esc(v.family_name || '')}</b></div>
      <div class="variant-row mono"><span>OPERATORS</span><div class="ops-row">${ops}</div></div>
      ${v.injected_lines && v.injected_lines.length
        ? `<div class="variant-row mono"><span>INJECTED LINES</span><b>${esc(v.injected_lines.join(', '))}</b></div>`
        : ''}
      ${checks ? `<div class="variant-row mono"><span>CRITIC</span><div class="ops-row">${checks}</div></div>` : ''}
      ${critic.rejected_reason ? `<p class="method">${esc(critic.rejected_reason)}</p>` : ''}
      ${v.mock ? '<p class="mail-only">Fixture mode builds the label and checks coherence against the baseline. Injecting it into the replay and watching the detector respond needs the live API.</p>' : ''}
    </article>`;
}
