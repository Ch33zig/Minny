// Live monitor. The point of this view is that incident cards GROW as correlated
// alerts arrive: one story assembling itself, not twenty warnings in a list.

import { api, openStream, seedLines } from '../api.js';
import { $, esc, fmtTs, sevChip, toast } from '../dom.js';
import { evidenceToggle, mountEvidence } from '../evidence.js';
import { bornIncident, enterRow, growIncident } from '../motion.js';

const SPEEDS = [
  { value: 1, label: '1 h/s' },
  { value: 6, label: '6 h/s' },
  { value: 24, label: '24 h/s' },
  { value: 120, label: '120 h/s' },
];
const TICKER_MAX = 80;

let stream = null;
let root = null;
let running = false;
let speed = 6;
const incidents = new Map();
const alertsById = new Map();

export async function render(container) {
  root = container;
  container.innerHTML = `
    <div class="mon-grid">
      <section class="panel replay">
        <div class="replay-left">
          <button class="ctl primary-ctl" id="playBtn" type="button"><span id="playIcon">▶</span><span id="playText">Play</span></button>
          <button class="ctl" id="resetBtn" type="button">⟲ Reset</button>
          <label class="speed">
            <span class="meta">SPEED</span>
            <select id="speedSel">${SPEEDS.map((s) => `<option value="${s.value}"${s.value === speed ? ' selected' : ''}>${s.label}</option>`).join('')}</select>
          </label>
          <span class="replay-hint meta">log hours per wall second</span>
        </div>
        <div class="replay-right">
          <span class="cursor meta" id="cursorTs">n/a</span>
          <span class="chip stream-chip" id="connChip">idle</span>
        </div>
        <div class="progress"><i id="progressBar"></i></div>
      </section>

      <section class="panel col ticker-col">
        <div class="col-head">
          <p class="section-label">EVENT TICKER</p>
          <span class="col-count meta" id="tickCount">0</span>
        </div>
        <div class="col-body" id="ticker"><div class="empty">Press play to replay the window.</div></div>
      </section>

      <section class="panel col inc-col">
        <div class="col-head">
          <p class="section-label">INCIDENTS</p>
          <span class="col-count meta" id="incCount">0</span>
        </div>
        <div class="col-body" id="incidents">
          <p class="col-intro">Correlated alerts collapse into one incident. Watch a card grow rather than reading twenty warnings.</p>
          <div class="empty" id="incEmpty">No incidents yet.</div>
        </div>
      </section>
    </div>`;

  mountEvidence(container);
  $('#playBtn', container).addEventListener('click', togglePlay);
  $('#resetBtn', container).addEventListener('click', resetReplay);
  $('#speedSel', container).addEventListener('change', (e) => {
    speed = Number(e.target.value);
    if (stream) stream.setSpeed(speed);
  });

  // Pre-cache alerts so incident frames can name their signals even if the
  // matching alert frame was missed after a reconnect.
  try {
    (await api.alerts()).forEach((a) => alertsById.set(a.alert_id, a));
  } catch (err) { /* alerts are a convenience here, not a dependency */ }

  stream = openStream({ onFrame, onState, speed });

  // ?autoplay=1 starts the replay on open, so a walkthrough can land on the
  // monitor already running instead of on a static screen.
  if (new URLSearchParams(location.search).get('autoplay') === '1') stream.start();
}

// The replay is never started for you: an analyst presses play, and it keeps
// running in the background while other views are open.
export function enter() {}
export function leave() {}

export function togglePlay() {
  if (!stream) return;
  if (running) stream.pause(); else stream.start();
}

function resetReplay() {
  if (!stream) return;
  stream.reset();
  incidents.clear();
  const list = $('#incidents', root);
  list.querySelectorAll('.inc').forEach((n) => n.remove());
  $('#incEmpty', root).hidden = false;
  $('#incCount', root).textContent = '0';
  $('#ticker', root).innerHTML = '<div class="empty">Press play to replay the window.</div>';
  $('#tickCount', root).textContent = '0';
  $('#progressBar', root).style.width = '0%';
  $('#cursorTs', root).textContent = 'n/a';
}

function onState(state) {
  if (!root) return;
  const chip = $('#connChip', root);
  if (state.gap) {
    chip.textContent = `GAP: expected seq ${state.gap.expected}, got ${state.gap.got}`;
    chip.className = 'chip stream-chip gap';
    toast(`Stream gap after reconnect: expected seq ${state.gap.expected}, got ${state.gap.got}.`, 'bad');
    return;
  }
  if (state.running !== undefined) {
    running = state.running;
    $('#playIcon', root).textContent = running ? '❙❙' : '▶';
    $('#playText', root).textContent = running ? 'Pause' : 'Play';
  }
  if (state.connected === false) {
    chip.textContent = 'RECONNECTING';
    chip.className = 'chip stream-chip bad';
  } else if (state.connected) {
    chip.textContent = state.source === 'fixture'
      ? (state.done ? 'REPLAY COMPLETE' : `FIXTURE REPLAY${running ? '' : ' · PAUSED'}`)
      : `SSE${running ? ' · LIVE' : ' · PAUSED'}`;
    chip.className = `chip stream-chip${running ? ' live' : ''}`;
  }
  if (state.total) {
    $('#progressBar', root).style.width = `${Math.round((state.index / state.total) * 100)}%`;
  }
  if (state.cursor_ts) $('#cursorTs', root).textContent = fmtTs(state.cursor_ts, { withOffset: true });
}

function onFrame(frame) {
  if (!root) return;
  if (frame.type === 'heartbeat') return;
  if (frame.type === 'replay_state') return onState({ ...frame.data, connected: true, cursor_ts: frame.data.cursor_ts });
  if (frame.type === 'event') return pushEvent(frame.data);
  if (frame.type === 'alert') return pushAlert(frame.data);
  if (frame.type === 'incident') return upsertIncident(frame.data);
}

// ------------------------------------------------------------------ ticker

let tickCount = 0;

function tickerNode() {
  const list = $('#ticker', root);
  const empty = list.querySelector('.empty');
  if (empty) empty.remove();
  return list;
}

function pushEvent(ev) {
  seedLines([ev]);
  const list = tickerNode();
  tickCount += 1;
  const row = document.createElement('div');
  row.className = 'tick';
  row.innerHTML = `
    <span class="tick-ln meta">${esc(ev.line)}</span>
    <span class="tick-ts meta">${esc((ev.ts || '').slice(11, 19))}</span>
    <span class="tick-user">${esc(ev.user || 'n/a')}</span>
    <span class="tick-path meta" title="${esc(ev.path || '')}">${esc(ev.path || '')}</span>
    <span class="tick-status meta s${statusClass(ev.status)}">${esc(ev.status)}</span>`;
  list.prepend(row);
  enterRow(row);
  trim(list);
  $('#tickCount', root).textContent = String(tickCount);
}

function pushAlert(alert) {
  alertsById.set(alert.alert_id, alert);
  const list = tickerNode();
  const row = document.createElement('div');
  row.className = 'tick tick-alert';
  row.innerHTML = `
    <span class="tick-sig meta">${esc(alert.signal)}</span>
    <span class="tick-ts meta">${esc((alert.ts || '').slice(11, 19))}</span>
    <span class="tick-alert-name">${esc(alert.signal_name)}</span>
    ${sevChip(alert.severity)}`;
  list.prepend(row);
  enterRow(row);
  trim(list);
}

function trim(list) {
  while (list.children.length > TICKER_MAX) list.lastElementChild.remove();
}

function statusClass(status) {
  const s = Number(status);
  if (s >= 500 || s === 400) return 'err';
  if (s === 401 || s === 403) return 'deny';
  if (s >= 300 && s < 400) return 'redir';
  return 'ok';
}

// --------------------------------------------------------------- incidents

function upsertIncident(inc) {
  const list = $('#incidents', root);
  const previous = incidents.get(inc.incident_id);
  incidents.set(inc.incident_id, inc);
  $('#incEmpty', root).hidden = true;
  $('#incCount', root).textContent = String(incidents.size);

  let node = list.querySelector(`[data-inc="${cssEscape(inc.incident_id)}"]`);
  const isNew = !node;
  if (isNew) {
    node = document.createElement('article');
    node.className = 'inc';
    node.dataset.inc = inc.incident_id;
    list.appendChild(node);
  }

  // The card is measured either side of the swap so the spring has a real
  // start and end. This is the animation the whole view exists for.
  const before = isNew ? 0 : node.getBoundingClientRect().height;
  const seen = beatsBefore(node);
  node.innerHTML = incidentHtml(inc);

  const synthetic = !!(inc.labels && inc.labels.synthetic);
  node.classList.toggle('synthetic', synthetic);
  node.classList.toggle('hatch', synthetic);
  node.classList.toggle('inc-high', String(inc.severity || '').toLowerCase() === 'high');

  const grewBy = previous ? (inc.alerts || []).length - (previous.alerts || []).length : 0;
  if (!isNew && grewBy > 0) {
    const badge = node.querySelector('.inc-grew');
    if (badge) badge.textContent = `+${grewBy} correlated`;
  }

  if (isNew) {
    bornIncident(node);
    node.scrollIntoView({ block: 'nearest' });
  } else {
    const fresh = Array.from(node.querySelectorAll('.nbeat')).slice(seen);
    growIncident(node, before, node.getBoundingClientRect().height, fresh);
  }
}

function incidentHtml(inc) {
  const synthetic = !!(inc.labels && inc.labels.synthetic);
  const attacker = inc.attacker || {};
  const victim = inc.victim || {};
  const alerts = (inc.alerts || []).map((id) => {
    const a = alertsById.get(id);
    if (!a) return `<span class="asig unknown" title="alert ${esc(id)} has not arrived on the stream yet"><i>${esc(id)}</i></span>`;
    return `<span class="asig known" title="${esc(a.explanation)}">${esc(a.signal)}<i>${esc(a.signal_name)}</i></span>`;
  }).join('');
  const beats = (inc.narrative || []).map((n) => `
    <div class="nbeat">
      <span class="nbeat-ts meta">${esc(fmtTs(n.ts))}</span>
      <p>${esc(n.text)}</p>
      ${evidenceToggle({ lines: n.lines || [], label: 'Raw' })}
    </div>`).join('');

  return `
    <div class="inc-head">
      <div class="inc-tags">
        ${sevChip(inc.severity)}
        <span class="inc-id meta">${esc(inc.incident_id)}</span>
        ${synthetic ? `<span class="synth-badge hatch">SYNTHETIC · ${esc((inc.labels && inc.labels.variant_id) || 'injected')}</span>` : ''}
      </div>
      <div class="inc-counts">
        <span class="inc-grew"></span>
        <span class="inc-alerts meta">${(inc.alerts || []).length} alerts</span>
      </div>
    </div>
    <h3 class="inc-title">${esc(inc.title || 'Incident')}</h3>
    <div class="inc-actors meta">
      <span class="ia attacker">${esc(attacker.user || '?')}<i>${esc(attacker.ip || '')}</i></span>
      <span class="ia-arrow">→</span>
      <span class="ia victim">${esc(victim.user || '?')}<i>${esc(victim.ip || '')}</i></span>
      <span class="ia-arrow">→</span>
      <span class="ia asset" title="${esc(inc.asset || '')}">${esc(inc.asset || 'n/a')}</span>
    </div>
    <div class="inc-sigs">${alerts || '<span class="asig unknown">no alerts yet</span>'}</div>
    <div class="inc-narrative">${beats || '<div class="empty">Narrative assembling…</div>'}</div>
    <div class="inc-foot meta">
      <span>opened ${esc(fmtTs(inc.opened_ts))}</span>
      <span>last ${esc(fmtTs(inc.last_ts))}</span>
      <span>${(inc.evidence_lines || []).length} evidence lines</span>
    </div>`;
}

/** How many narrative beats the card was already showing. */
function beatsBefore(node) {
  return node.querySelectorAll('.nbeat').length;
}

function cssEscape(value) {
  return String(value).replace(/["\\]/g, '\\$&');
}
