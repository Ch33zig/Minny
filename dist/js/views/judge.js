// Judge's panel. Dropdowns are populated from the fitted baseline, so an
// incoherent attack cannot be constructed in the first place: the victim is
// always someone who can read the target, the attacker always someone who cannot.

import { api, MOCK } from '../api.js';
import { $, esc, toast } from '../dom.js';
import { layStamp, pinCard } from '../motion.js';

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
      <section class="form-slip">
        <span class="pin red left"></span><span class="pin right"></span>
        <span class="stamp big filed-stamp" id="jStamp" hidden>FILED</span>
        <div class="form-head">
          <h2 class="form-title">Evidence request</h2>
          <span class="form-sub tw">Red team, one variant</span>
        </div>
        <p class="form-note">Every pairing on offer comes from the access model fitted before March, so the attack you build could really have happened.</p>

        <div class="form-body">
          <label class="field">
            <span class="tw">Target file</span>
            <select id="jTarget">${access.targets.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join('')}</select>
          </label>
          <div class="field-pair">
            <label class="field">
              <span class="tw">Victim, authorized to read it</span>
              <select id="jVictim"></select>
            </label>
            <label class="field">
              <span class="tw">Attacker, who is not</span>
              <select id="jAttacker"></select>
            </label>
          </div>
          <div class="field-pair">
            <label class="field">
              <span class="tw">Family</span>
              <select id="jFamily">${FAMILIES.map(([id, name]) => `<option value="${id}">${id} ${name}</option>`).join('')}</select>
            </label>
            <div class="field">
              <span class="tw">Operators, at most ${MAX_OPERATORS}</span>
              <div class="ops" id="jOps">
                ${OPERATORS.map((o) => `<label class="op"><input type="checkbox" value="${esc(o)}"><span>${esc(o)}</span></label>`).join('')}
              </div>
            </div>
          </div>
        </div>

        <div class="form-foot">
          <button class="ctl primary-ctl" id="jRun" type="button">Generate and inject</button>
          <span class="hand" id="jNote"></span>
        </div>
      </section>

      <section class="judge-out">
        <h2 class="board-head">Variants<span class="board-count" id="jCount">0</span></h2>
        <div class="variant-stack" id="jResults"><div class="empty">Nothing generated yet.</div></div>
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
    `${victims.length} can read it, ${attackers.length} cannot`;
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
    pinCard(list.firstElementChild);
    const stamp = $('#jStamp', container);
    stamp.hidden = false;
    layStamp(stamp);
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
  const checks = (critic.checks_passed || []).map((c) => `<span class="tick-mark">${esc(c)}</span>`).join('');
  const ops = (v.operators || request.operators || []).map((o) => `<span class="op-chip">${esc(o)}</span>`).join('')
    || '<span class="op-chip none">no operators</span>';
  const detail = v.mock
    ? '<p class="slip-body">Fixture mode builds the label and checks it for coherence against the baseline. Injecting it into the replay and watching the detector respond needs the live API.</p>'
    : '';
  return `
    <article class="variant-slip" style="--rot:${rot(v.variant_id || 'v')}">
      <span class="pin"></span>
      <div class="index-top">
        <span class="card-id">${esc(v.variant_id || 'variant')}</span>
        <span class="stamp ${critic.accepted ? 'ink outline' : 'faint'}">${critic.accepted ? 'CRITIC ACCEPTED' : 'CRITIC REJECTED'}</span>
      </div>
      <p class="claim small">${esc(v.attacker || request.attacker)} to ${esc(v.victim || request.victim)}</p>
      <div class="variant-target">${esc(v.target || request.target)}</div>
      <div class="variant-rows">
        <div><span class="tw">Family</span><b>${esc(v.family || request.family)} ${esc(v.family_name || '')}</b></div>
        <div><span class="tw">Operators</span><div class="ops-row">${ops}</div></div>
        ${v.injected_lines && v.injected_lines.length
          ? `<div><span class="tw">Injected lines</span><b>${esc(v.injected_lines.join(', '))}</b></div>`
          : ''}
        ${checks ? `<div><span class="tw">Critic</span><div class="ops-row">${checks}</div></div>` : ''}
      </div>
      ${critic.rejected_reason ? `<p class="hand aside">${esc(critic.rejected_reason)}</p>` : ''}
      <span class="stamp pencil-stamp variant-mode">${v.mock ? 'LABEL ONLY, NO BACKEND' : 'INJECTED'}</span>
      ${detail ? `<div class="ev"><div class="ev-body ev-open">${detail}</div></div>` : ''}
    </article>`;
}

function rot(seed, max = 1.2) {
  let h = 0;
  const str = String(seed);
  for (let i = 0; i < str.length; i += 1) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  return `${((((h % 997) / 997) * 2 - 1) * max).toFixed(2)}deg`;
}
