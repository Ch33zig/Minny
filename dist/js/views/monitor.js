// Live monitor. The board assembles itself: the printout runs, an alert pins a
// card onto the cork, string draws from that card to the incident it belongs to,
// and the incident card grows. One story assembling, not twenty warnings.
//
// Every string here is the correlator's own answer: alert.incident_id. No card
// is joined to an incident the data did not put it in.

import { api, openStream, seedLines } from '../api.js';
import { $, esc, fmtTs, NONE, noneTag, toast } from '../dom.js';
import { evidenceToggle, mountEvidence } from '../evidence.js';
import { bornIncident, drawStrings, enterRow, growIncident, pinCard } from '../motion.js';

const SPEEDS = [
  { value: 1, label: '1 h/s' },
  { value: 6, label: '6 h/s' },
  { value: 24, label: '24 h/s' },
  { value: 120, label: '120 h/s' },
];
const TICKER_MAX = 80;
const WALL_MAX = 14; // the wall stays readable; the incident card keeps the true count

let stream = null;
let root = null;
let running = false;
let speed = 6;
const incidents = new Map();
const alertsById = new Map();
const pinnedAlerts = [];
const drawnEdges = new Set();

export async function render(container) {
  root = container;
  container.innerHTML = `
    <div class="mon-grid">
      <section class="replay slip-wide">
        <div class="replay-left">
          <button class="ctl primary-ctl" id="playBtn" type="button"><span id="playIcon">&#9654;</span><span id="playText">Play</span></button>
          <button class="ctl" id="resetBtn" type="button">&#8635; Reset</button>
          <label class="speed">
            <span class="tw">Speed</span>
            <select id="speedSel">${SPEEDS.map((s) => `<option value="${s.value}"${s.value === speed ? ' selected' : ''}>${s.label}</option>`).join('')}</select>
          </label>
          <span class="replay-hint">log hours per wall second</span>
        </div>
        <div class="replay-right">
          <span class="cursor" id="cursorTs"><span class="none">&#183;</span></span>
          <span class="stamp ink outline" id="connChip">IDLE</span>
        </div>
        <div class="progress"><i id="progressBar"></i></div>
      </section>

      <section class="printout-col">
        <h2 class="board-head">Printout<span class="board-count" id="tickCount">0</span></h2>
        <div class="printout">
          <div class="printout-rows" id="ticker"><div class="empty">Press play to replay the window.</div></div>
        </div>
      </section>

      <section class="mon-board" id="monBoard">
        <svg class="string-layer" id="monStrings" aria-hidden="true"></svg>
        <h2 class="board-head">Alerts on the wall<span class="board-count" id="wallCount">0</span></h2>
        <div class="alert-wall" id="alertWall">
          <div class="empty" id="wallEmpty">Nothing pinned yet.</div>
        </div>
        <h2 class="board-head">Incidents<span class="board-count" id="incCount">0</span></h2>
        <div class="inc-stack" id="incidents">
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

  if (window.ResizeObserver) new ResizeObserver(() => paintStrings()).observe($('#monBoard', container));

  stream = openStream({ onFrame, onState, speed });

  // ?autoplay=1 starts the replay on open, so a walkthrough can land on the
  // monitor already running instead of on a static screen.
  if (new URLSearchParams(location.search).get('autoplay') === '1') stream.start();
}

// The replay is never started for you: an analyst presses play, and it keeps
// running in the background while other views are open.
export function enter() { paintStrings(); }
export function leave() {}

export function togglePlay() {
  if (!stream) return;
  if (running) stream.pause(); else stream.start();
}

function resetReplay() {
  if (!stream) return;
  stream.reset();
  incidents.clear();
  pinnedAlerts.length = 0;
  drawnEdges.clear();
  const list = $('#incidents', root);
  list.querySelectorAll('.inc').forEach((n) => n.remove());
  $('#incEmpty', root).hidden = false;
  $('#incCount', root).textContent = '0';
  $('#alertWall', root).querySelectorAll('.acard').forEach((n) => n.remove());
  $('#wallEmpty', root).hidden = false;
  $('#wallCount', root).textContent = '0';
  $('#ticker', root).innerHTML = '<div class="empty">Press play to replay the window.</div>';
  $('#tickCount', root).textContent = '0';
  $('#progressBar', root).style.width = '0%';
  $('#cursorTs', root).textContent = NONE;
  tickCount = 0;
  paintStrings();
}

function onState(state) {
  if (!root) return;
  const chip = $('#connChip', root);
  if (state.gap) {
    chip.textContent = `GAP AT SEQ ${state.gap.expected}`;
    chip.className = 'stamp faint';
    toast(`Stream gap after reconnect: expected seq ${state.gap.expected}, got ${state.gap.got}.`, 'bad');
    return;
  }
  if (state.running !== undefined) {
    running = state.running;
    $('#playIcon', root).innerHTML = running ? '&#10073;&#10073;' : '&#9654;';
    $('#playText', root).textContent = running ? 'Pause' : 'Play';
  }
  if (state.connected === false) {
    chip.textContent = 'RECONNECTING';
    chip.className = 'stamp outline';
  } else if (state.connected) {
    chip.textContent = state.source === 'fixture'
      ? (state.done ? 'REPLAY COMPLETE' : `REPLAY${running ? ' RUNNING' : ' PAUSED'}`)
      : `SSE${running ? ' LIVE' : ' PAUSED'}`;
    // Replay state is not a finding, so it never gets the red stamp.
    chip.className = running ? 'stamp ink solid' : 'stamp ink outline';
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

/* ------------------------------------------------------------- printout */

let tickCount = 0;

function pushEvent(ev) {
  seedLines([ev]);
  const list = $('#ticker', root);
  const blank = list.querySelector('.empty');
  if (blank) blank.remove();
  tickCount += 1;
  const row = document.createElement('div');
  row.className = 'tick';
  row.innerHTML = `
    <span class="tick-ln">${esc(ev.line)}</span>
    <span class="tick-ts">${esc((ev.ts || '').slice(11, 19))}</span>
    <span class="tick-user">${esc(ev.user) || noneTag}</span>
    <span class="tick-path" title="${esc(ev.path || '')}">${esc(ev.path || '')}</span>
    <span class="tick-status s${statusClass(ev.status)}">${esc(ev.status)}</span>`;
  list.prepend(row);
  enterRow(row);
  while (list.children.length > TICKER_MAX) list.lastElementChild.remove();
  $('#tickCount', root).textContent = String(tickCount);
}

function statusClass(status) {
  const s = Number(status);
  if (s >= 500 || s === 400) return 'err';
  if (s === 401 || s === 403) return 'deny';
  if (s >= 300 && s < 400) return 'redir';
  return 'ok';
}

/* ---------------------------------------------------- alerts on the wall */

function pushAlert(alert) {
  alertsById.set(alert.alert_id, alert);

  // The printout keeps its own trace of the alert, so the paper record and
  // the wall never disagree.
  const list = $('#ticker', root);
  const blank = list.querySelector('.empty');
  if (blank) blank.remove();
  const row = document.createElement('div');
  row.className = 'tick tick-alert';
  row.innerHTML = `
    <span class="tick-ln">${esc(alert.signal)}</span>
    <span class="tick-ts">${esc((alert.ts || '').slice(11, 19))}</span>
    <span class="tick-alert-name">${esc(alert.signal_name)}</span>
    <span class="tick-sev sev-${esc(String(alert.severity || '').toLowerCase())}">${esc(alert.severity)}</span>`;
  list.prepend(row);
  enterRow(row);
  while (list.children.length > TICKER_MAX) list.lastElementChild.remove();

  const wall = $('#alertWall', root);
  $('#wallEmpty', root).hidden = true;
  const high = String(alert.severity || '').toLowerCase() === 'high';
  const card = document.createElement('article');
  card.className = `acard sev-${esc(String(alert.severity || 'low').toLowerCase())}`;
  card.dataset.alert = alert.alert_id;
  card.dataset.inc = alert.incident_id || '';
  card.style.setProperty('--rot', rot(alert.alert_id));
  card.innerHTML = `
    <span class="pin ${high ? 'red' : ''}"></span>
    <div class="acard-top">
      <span class="asig">${esc(alert.signal)}</span>
      <span class="atime">${esc((alert.ts || '').slice(11, 16))}</span>
    </div>
    <div class="acard-name">${esc(alert.signal_name)}</div>
    <div class="acard-who">${esc(alert.user || '')}</div>`;
  card.title = alert.explanation || '';
  wall.appendChild(card);
  pinnedAlerts.push(card);
  pinCard(card);

  while (pinnedAlerts.length > WALL_MAX) {
    const old = pinnedAlerts.shift();
    drawnEdges.delete(`${old.dataset.alert}|${old.dataset.inc}`);
    old.remove();
  }
  $('#wallCount', root).textContent = String(pinnedAlerts.length);
  paintStrings();
}

/* ------------------------------------------------------------ incidents */

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
    node.style.setProperty('--rot', rot(inc.incident_id, 0.7));
    list.appendChild(node);
  }

  // The card is measured either side of the swap so the spring has a real
  // start and end. This is the animation the whole view exists for.
  const before = isNew ? 0 : node.getBoundingClientRect().height;
  const seen = node.querySelectorAll('.nbeat').length;
  node.innerHTML = incidentHtml(inc);

  const synthetic = !!(inc.labels && inc.labels.synthetic);
  node.classList.toggle('synthetic', synthetic);
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
  paintStrings();
}

function incidentHtml(inc) {
  const synthetic = !!(inc.labels && inc.labels.synthetic);
  const high = String(inc.severity || '').toLowerCase() === 'high';
  const attacker = inc.attacker || {};
  const victim = inc.victim || {};
  const alerts = (inc.alerts || []).map((id) => {
    const a = alertsById.get(id);
    if (!a) return `<span class="sigchip unknown" title="alert ${esc(id)} has not arrived on the stream yet">${esc(id).slice(0, 6)}</span>`;
    return `<span class="sigchip" title="${esc(a.explanation)}">${esc(a.signal)}<i>${esc(a.signal_name)}</i></span>`;
  }).join('');
  const beats = (inc.narrative || []).map((n) => `
    <div class="nbeat">
      <span class="nbeat-ts">${esc(fmtTs(n.ts))}</span>
      <p>${esc(n.text)}</p>
      ${evidenceToggle({ lines: n.lines || [], label: 'Raw' })}
    </div>`).join('');

  return `
    <span class="pin ${high ? 'red' : ''} left"></span>
    <span class="pin ${high ? 'red' : ''} right"></span>
    <div class="inc-head">
      <div class="inc-tags">
        <span class="stamp ${high ? 'solid' : 'ink outline'}">${esc(inc.severity || 'unknown')}</span>
        <span class="card-id">${esc(inc.incident_id)}</span>
        ${synthetic ? `<span class="stamp pencil-stamp">SIMULATION ${esc((inc.labels && inc.labels.variant_id) || '')}</span>` : ''}
      </div>
      <div class="inc-counts">
        <span class="inc-grew"></span>
        <b class="inc-alerts">${(inc.alerts || []).length}</b><span class="inc-alerts-label">alerts</span>
      </div>
    </div>
    <h3 class="inc-title">${esc(inc.title || 'Incident')}</h3>
    <div class="inc-chain">
      <span class="chain-node attacker">${esc(attacker.user || '?')}<i>${esc(attacker.ip || '')}</i></span>
      <span class="chain-arrow">to</span>
      <span class="chain-node victim">${esc(victim.user || '?')}<i>${esc(victim.ip || '')}</i></span>
      <span class="chain-arrow">to</span>
      <span class="chain-node asset" title="${esc(inc.asset || '')}">${esc(inc.asset) || noneTag}</span>
    </div>
    <div class="inc-sigs">${alerts || '<span class="sigchip unknown">no alerts yet</span>'}</div>
    <div class="inc-narrative">${beats || '<div class="empty">Narrative assembling.</div>'}</div>
    <div class="inc-foot">
      <span>opened ${esc(fmtTs(inc.opened_ts))}</span>
      <span>last ${esc(fmtTs(inc.last_ts))}</span>
      <span>${(inc.evidence_lines || []).length} evidence lines</span>
    </div>`;
}

/* --------------------------------------------------------------- string */

/**
 * One string per pinned alert card, running to the incident the correlator put
 * it in. The edge comes straight from alert.incident_id: nothing is joined up
 * for the look of it.
 */
function paintStrings() {
  if (!root) return;
  const board = $('#monBoard', root);
  const layer = $('#monStrings', root);
  if (!board || !layer) return;
  const base = board.getBoundingClientRect();
  layer.setAttribute('viewBox', `0 0 ${Math.round(base.width)} ${Math.round(base.height)}`);
  layer.setAttribute('width', Math.round(base.width));
  layer.setAttribute('height', Math.round(base.height));

  const parts = [];
  const fresh = [];
  for (const card of pinnedAlerts) {
    const incId = card.dataset.inc;
    if (!incId) continue;
    const target = board.querySelector(`.inc[data-inc="${cssEscape(incId)}"]`);
    if (!target) continue;
    const a = card.getBoundingClientRect();
    const b = target.getBoundingClientRect();
    const from = { x: a.left - base.left + a.width / 2, y: a.top - base.top + 6 };
    const to = { x: b.left - base.left + b.width / 2, y: b.top - base.top + 4 };
    const key = `${card.dataset.alert}|${incId}`;
    const isNew = !drawnEdges.has(key);
    if (isNew) { drawnEdges.add(key); fresh.push(key); }
    const cx = (from.x + to.x) / 2;
    const cy = (from.y + to.y) / 2 + 18;
    const high = card.classList.contains('sev-high');
    parts.push(`<path class="string-line ${high ? '' : 'thread'}" data-key="${esc(key)}" d="M ${from.x} ${from.y} Q ${cx} ${cy} ${to.x} ${to.y}"></path>`);
  }
  layer.innerHTML = parts.join('');
  if (fresh.length) {
    drawStrings(Array.from(layer.querySelectorAll('.string-line'))
      .filter((p) => fresh.includes(p.dataset.key)));
  }
}

function rot(seed, max = 1.4) {
  let h = 0;
  const s = String(seed);
  for (let i = 0; i < s.length; i += 1) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return `${((((h % 997) / 997) * 2 - 1) * max).toFixed(2)}deg`;
}

function cssEscape(value) {
  return String(value).replace(/["\\]/g, '\\$&');
}
