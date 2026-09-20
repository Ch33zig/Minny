// The case board. Four entities pinned to cork with red string between them,
// findings as index cards, the timeline as a dated strip, the verdict typed on
// a report page.
//
// Two rules shape this file:
//
//   1. Every card resolves to real log lines. Nothing on the board is
//      decoration standing in for evidence.
//   2. A string is only drawn between two entities when a claim in the case
//      file names both of them. The supporting claim ids travel with the
//      string, and clicking it opens their raw bytes. See `relations()`.

import { api } from '../api.js';
import { esc, fmtTs, NONE, noneTag } from '../dom.js';
import { evidenceToggle, mountEvidence, toggleAll } from '../evidence.js';
import { drawStrings, layStamp } from '../motion.js';

const CONF_STAMP = {
  high: { text: 'CONFIRMED', cls: 'solid' },
  medium: { text: 'PROBABLE', cls: 'outline' },
  low: { text: 'UNVERIFIED', cls: 'faint' },
};

let boardRoot = null;
let relayout = null;

export async function render(container) {
  const cf = await api.caseFile();
  const actors = cf.actors || {};
  const ents = entities(actors);
  const rel = relations(cf, ents);

  container.innerHTML = `
    <div class="case-board">
      <section class="wall" id="wall">
        <svg class="string-layer" id="stringLayer" aria-hidden="true"></svg>
        <div class="wall-row">
          ${ents.map((e) => entityCard(e, cf)).join('')}
        </div>
        <div class="wall-foot">
          <p class="wall-key">
            <span class="key-swatch"></span>
            <span class="tw">String = a claim names both ends. Pull one.</span>
          </p>
          <div class="wall-slip" id="wallSlip" hidden></div>
        </div>
      </section>

      <div class="case-cols">
        <section class="board-col findings-col">
          <h2 class="board-head">Findings<span class="board-count">${(cf.findings || []).length}</span></h2>
          ${(cf.findings || []).map(finding).join('') || empty('No findings in this case file.')}
        </section>

        <section class="board-col right-col">
          ${verdict(cf)}
          <h2 class="board-head">Cleared<span class="board-count">${(cf.dismissed || []).length}</span></h2>
          <div class="cleared-cluster">
            ${(cf.dismissed || []).map(dismissed).join('') || empty('Nothing was ruled out.')}
          </div>
          <h2 class="board-head">Still open<span class="board-count">${(cf.unknowns || []).length}</span></h2>
          <div class="unknown-cluster">
            ${(cf.unknowns || []).map(unknown).join('') || empty('Nothing left open.')}
          </div>
        </section>
      </div>

      <section class="strip">
        <h2 class="board-head">Timeline<span class="board-count">${(cf.timeline || []).length}</span></h2>
        <div class="strip-scroll" id="stripScroll">
          <svg class="string-layer" id="stripLayer" aria-hidden="true"></svg>
          <div class="strip-row">${(cf.timeline || []).map(beat).join('') || empty('No timeline recorded.')}</div>
        </div>
      </section>
    </div>`;

  mountEvidence(container);
  boardRoot = container;
  wireStrings(container, rel);
  // Cards do not animate in here: the board is already on the wall when the
  // view opens, and a page-load cascade is exactly what the design forbids.
  // The one exception is the verdict stamp, which lands once.
  layStamp(container.querySelector('.verdict-stamp'));

  // ?open=1 opens every evidence slip on load, for a walkthrough that starts
  // with the proof already on screen rather than a click away.
  if (new URLSearchParams(location.search).get('open') === '1') toggleAll(container, true);
}

export function enter() { if (relayout) relayout(); }

/* ------------------------------------------------------------- entities */

function entities(actors) {
  const out = [];
  const a = actors.attacker || {};
  const v = actors.victim || {};
  if (a.user) out.push({ key: 'attacker', kind: 'suspect', label: a.user, actor: a });
  if (v.user) out.push({ key: 'victim', kind: 'suspect', label: v.user, actor: v });
  if (actors.vector && (actors.vector.template || actors.vector.obj_id !== undefined)) {
    out.push({ key: 'vector', kind: 'vector', label: vectorLabel(actors.vector), vector: actors.vector });
  }
  if (actors.asset) out.push({ key: 'asset', kind: 'asset', label: actors.asset, asset: actors.asset });
  return out;
}

function vectorLabel(vector) {
  if (!vector) return NONE;
  const t = vector.template || '';
  if (vector.obj_id === null || vector.obj_id === undefined) return t || NONE;
  return t.includes('{id}') ? t.replace('{id}', vector.obj_id) : `${t} · ${vector.obj_id}`;
}

/**
 * How a sentence is recognised as naming an entity. Deliberately conservative:
 * a user by account name or by their baseline IP, the asset by its path or by
 * every significant word in its file name, the vector by its object id or a
 * named segment of its template. Nothing here guesses.
 */
function matcher(ent) {
  const words = [];
  if (ent.kind === 'suspect') {
    words.push(ent.actor.user);
    if (ent.actor.ip) words.push(ent.actor.ip);
    return (text) => words.some((w) => text.includes(w.toLowerCase()));
  }
  if (ent.kind === 'asset') {
    const path = String(ent.asset).toLowerCase();
    const base = path.split('/').pop().replace(/\.[a-z0-9]+$/, '');
    const tokens = base.split(/[_\-.]/).filter((t) => t.length > 1);
    return (text) => text.includes(path) || (tokens.length > 0 && tokens.every((t) => text.includes(t)));
  }
  const id = ent.vector.obj_id;
  const generic = new Set(['view', 'edit', 'new', 'api', 'assets', 'index', 'id']);
  const segs = String(ent.vector.template || '').split('/')
    .filter((s) => s && !s.includes('{') && s.length >= 4 && !generic.has(s.toLowerCase()))
    .map((s) => s.toLowerCase());
  return (text) => (id !== null && id !== undefined && text.includes(String(id)))
    || segs.some((s) => text.includes(s));
}

const RANK = { high: 3, medium: 2, low: 1 };

/**
 * One edge per pair of entities that a claim or a timeline beat names together,
 * carrying the ids of every claim that put it there and the lines behind them.
 * An edge supported only by an inference is drawn broken, not solid.
 */
function relations(cf, ents) {
  const tests = ents.map((e) => ({ key: e.key, test: matcher(e) }));
  const sources = [];
  for (const f of cf.findings || []) {
    sources.push({ id: f.id, text: f.claim || '', lines: f.evidence_lines || [], conf: f.confidence, kind: 'finding' });
  }
  for (const t of cf.timeline || []) {
    const lines = t.evidence_lines && t.evidence_lines.length ? t.evidence_lines : (t.line ? [t.line] : []);
    sources.push({ id: `line ${t.line}`, text: t.action || '', lines, conf: t.confidence, kind: 'beat' });
  }

  const edges = new Map();
  for (const src of sources) {
    const text = String(src.text).toLowerCase();
    const hit = tests.filter((t) => t.test(text)).map((t) => t.key);
    for (let i = 0; i < hit.length; i += 1) {
      for (let j = i + 1; j < hit.length; j += 1) {
        const key = `${hit[i]}|${hit[j]}`;
        if (!edges.has(key)) edges.set(key, { from: hit[i], to: hit[j], basis: [], conf: 'low' });
        const edge = edges.get(key);
        edge.basis.push(src);
        const c = String(src.conf || 'low').toLowerCase();
        if ((RANK[c] || 1) > (RANK[edge.conf] || 1)) edge.conf = c;
      }
    }
  }
  return Array.from(edges.values());
}

/* ------------------------------------------------------- entity cards */

function rot(seed, max = 1.4) {
  let h = 0;
  const s = String(seed);
  for (let i = 0; i < s.length; i += 1) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return `${((((h % 997) / 997) * 2 - 1) * max).toFixed(2)}deg`;
}

function initials(user) {
  if (!user) return '??';
  const parts = String(user).split(/[_.\s]/);
  return ((parts[0] || '')[0] || '?').toUpperCase() + ((parts[1] || parts[0] || '')[0] || '').toUpperCase();
}

function firstSentence(text) {
  const s = String(text || '').trim();
  if (!s) return { head: '', rest: '' };
  const m = /^[\s\S]*?[.!?](?=\s|$)/.exec(s);
  const head = m ? m[0] : s;
  return { head, rest: s.slice(head.length).trim() };
}

function entityCard(ent, cf) {
  if (ent.kind === 'suspect') return suspectCard(ent);
  if (ent.kind === 'vector') return vectorCard(ent, cf);
  return assetCard(ent, cf);
}

function suspectCard(ent) {
  const a = ent.actor;
  const attacker = ent.key === 'attacker';
  const stats = a.stats || [];
  const shown = stats.slice(0, 2);
  const rest = stats.slice(2);
  const detail = `
    ${a.summary ? `<p class="slip-body">${esc(a.summary)}</p>` : ''}
    ${rest.length ? `<dl class="slip-stats">${rest.map((s) =>
      `<div><dt>${esc(s.label)}</dt><dd>${esc(s.value)}</dd></div>`).join('')}</dl>` : ''}`;
  return `
    <article class="ent suspect pinned ${esc(ent.key)}" data-ent="${esc(ent.key)}" style="--rot:${rot(a.user)}">
      <span class="pin ${attacker ? 'red' : ''}"></span>
      <span class="tape tl"></span><span class="tape br"></span>
      <div class="mugshot">
        <span class="monogram">${esc(initials(a.user))}</span>
        <span class="stamp ${attacker ? 'solid' : 'ink outline'} role-stamp">${attacker ? 'SUSPECT' : 'ACCOUNT USED'}</span>
      </div>
      <div class="ent-name">${esc(a.user)}</div>
      <div class="ent-sub">${esc(a.ip || 'no IP recorded')}</div>
      <div class="ent-nums">
        ${shown.map((s) => `
          <div class="big-stat">
            <b class="${String(s.value).length > 5 ? 'wide' : ''}">${esc(s.value)}</b>
            <span>${esc(s.label)}</span>
          </div>`).join('')}
      </div>
      ${evidenceToggle({ lines: a.evidence_lines || [], label: 'Card evidence', detail })}
    </article>`;
}

function vectorCard(ent, cf) {
  const v = ent.vector;
  const cited = citedBy(cf, ent);
  const note = beatNote(cf, ent);
  return `
    <article class="ent prop pinned vector" data-ent="vector" style="--rot:${rot('vector' + v.obj_id)}">
      <span class="pin"></span>
      <span class="tape tr"></span>
      <div class="prop-kind tw">Vector</div>
      <div class="prop-big">${esc(v.obj_id === null || v.obj_id === undefined ? NONE : v.obj_id)}</div>
      <div class="prop-label">${esc(v.template || '')}</div>
      ${note ? `<p class="hand aside">${esc(note)}</p>` : ''}
      ${evidenceToggle({ lines: cited.lines, label: cited.label })}
    </article>`;
}

function assetCard(ent, cf) {
  const path = String(ent.asset);
  const file = path.split('/').pop();
  const dir = path.slice(0, path.length - file.length);
  const cited = citedBy(cf, ent);
  const note = beatNote(cf, ent);
  return `
    <article class="ent prop pinned asset" data-ent="asset" style="--rot:${rot(path)}">
      <span class="pin red"></span>
      <span class="tape tl"></span>
      <div class="prop-kind tw">Asset</div>
      ${/confidential/i.test(file) ? '<span class="stamp solid asset-stamp">CONFIDENTIAL</span>' : ''}
      <div class="prop-file">${esc(file)}</div>
      <div class="prop-label">${esc(dir)}</div>
      ${note ? `<p class="hand aside">${esc(note)}</p>` : ''}
      ${evidenceToggle({ lines: cited.lines, label: cited.label })}
    </article>`;
}

/** The lines behind every finding whose claim names this entity. */
function citedBy(cf, ent) {
  const test = matcher(ent);
  const hits = (cf.findings || []).filter((f) => test(String(f.claim || '').toLowerCase()));
  const lines = [];
  for (const f of hits) for (const n of f.evidence_lines || []) if (!lines.includes(n)) lines.push(n);
  return { lines, label: hits.length ? `Cited by ${hits.map((f) => f.id).join(', ')}` : 'Card evidence' };
}

/** The investigator's own aside, taken verbatim from the timeline. */
function beatNote(cf, ent) {
  const test = matcher(ent);
  const beat = (cf.timeline || []).find((t) => t.note && test(String(t.action || '').toLowerCase()));
  return beat ? beat.note : null;
}

/* -------------------------------------------------------------- cards */

function empty(text) {
  return `<div class="empty">${esc(text)}</div>`;
}

function confStamp(level, extra = '') {
  const l = String(level || 'low').toLowerCase();
  const s = CONF_STAMP[l] || CONF_STAMP.low;
  return `<span class="stamp ${s.cls}" title="confidence ${esc(l)}${extra ? ', ' + esc(extra) : ''}">${s.text}</span>`;
}

function finding(f) {
  const level = String(f.confidence || 'low').toLowerCase();
  const mailOnly = (!f.evidence_lines || !f.evidence_lines.length) && (f.evidence_emails || []).length;
  const method = firstSentence(f.method);
  const soft = level !== 'high';
  const detail = `
    <div class="slip-head-row"><span class="tw">Method</span><span class="meta">${esc(f.query || '')}</span></div>
    <p class="slip-body">${esc(f.method || '')}</p>`;
  return `
    <article class="card index pinned conf-${esc(level)}" style="--rot:${rot(f.id || f.claim)}">
      <span class="pin"></span>
      <div class="index-top">
        <span class="card-id">${esc(f.id || '')}</span>
        ${confStamp(f.confidence)}
      </div>
      <p class="claim">${esc(f.claim)}</p>
      ${soft ? `<p class="hand aside">${esc(method.head)}</p>` : ''}
      ${mailOnly ? '<p class="hand aside">Mailbox records only.</p>' : ''}
      ${evidenceToggle({ lines: f.evidence_lines || [], emails: f.evidence_emails || [], detail })}
    </article>`;
}

function verdict(cf) {
  const vd = cf.verdict || {};
  const actors = cf.actors || {};
  const open = (cf.unknowns || []).length;
  const detail = vd.basis ? `<div class="slip-head-row"><span class="tw">Basis</span></div><p class="slip-body">${esc(vd.basis)}</p>` : '';
  return `
    <article class="report pinned" style="--rot:-0.4deg">
      <span class="pin left"></span><span class="pin right"></span>
      <span class="stamp big verdict-stamp corner">${open ? 'CASE OPEN' : 'CASE CLOSED'}</span>
      <div class="report-head">
        <h2 class="report-title">Verdict</h2>
        ${confStamp(vd.confidence)}
      </div>
      <div class="report-facts">
        <div><span class="tw">Attacker</span><b>${esc((actors.attacker || {}).user) || noneTag}</b></div>
        <div><span class="tw">Victim account</span><b>${esc((actors.victim || {}).user) || noneTag}</b></div>
        <div class="wide"><span class="tw">Asset</span><b class="path">${esc(actors.asset) || noneTag}</b></div>
        <div class="wide"><span class="tw">Vector</span><b class="path">${esc(vectorLabel(actors.vector))}</b></div>
      </div>
      <p class="report-text">${esc(vd.summary || 'No verdict recorded.')}</p>
      ${open ? `<p class="hand aside report-aside">${open} question${open === 1 ? '' : 's'} still open, below.</p>` : ''}
      ${evidenceToggle({ lines: [], label: 'What the basis rests on', detail })}
    </article>`;
}

function beat(t) {
  const lines = t.evidence_lines && t.evidence_lines.length ? t.evidence_lines : (t.line ? [t.line] : []);
  const level = String(t.confidence || 'high').toLowerCase();
  const stamp = level === 'high' ? '' : confStamp(t.confidence);
  return `
    <article class="beat pinned conf-${esc(level)}" style="--rot:${rot('b' + t.line)}">
      <span class="pin"></span>
      <div class="beat-when">
        <b class="beat-time">${esc(String(t.ts || '').slice(11, 19))}</b>
        <span class="beat-day tw">${esc(fmtTs(t.ts).replace(/\s\d\d:\d\d:\d\d$/, ''))}</span>
      </div>
      <div class="beat-actor">${esc(t.actor) || noneTag}</div>
      <p class="beat-action">${esc(t.action || '')}</p>
      ${t.note ? `<p class="hand aside">${esc(t.note)}</p>` : ''}
      ${stamp}
      ${evidenceToggle({ lines, label: `Line ${lines[0] || ''}` })}
    </article>`;
}

function dismissed(d) {
  const why = firstSentence(d.why);
  const detail = `
    <div class="slip-head-row"><span class="tw">Why it is nothing</span><span class="meta">${esc(d.query || '')}</span></div>
    <p class="slip-body">${esc(d.why || '')}</p>`;
  return `
    <article class="card cleared pinned" style="--rot:${rot(d.id || d.lead, 1.2)}">
      <span class="pin"></span>
      <span class="stamp big ink cleared-stamp">CLEARED</span>
      <div class="index-top"><span class="card-id">${esc(d.id || '')}</span></div>
      <p class="claim small">${esc(d.lead)}</p>
      <p class="hand aside">${esc(why.head)}</p>
      ${evidenceToggle({ lines: d.evidence_lines || [], label: 'What we checked', detail })}
    </article>`;
}

function unknown(u) {
  const text = firstSentence(u.text);
  const detail = `<p class="slip-body">${esc(u.text || '')}</p>`;
  return `
    <article class="card open-note pinned" style="--rot:${rot(u.id || u.text, 1.2)}">
      <span class="pin"></span>
      <div class="index-top">
        <span class="card-id">${esc(u.id || '')}</span>
        ${u.closed_by ? '<span class="stamp outline ink">MAILBOX</span>' : '<span class="hand open-mark">still open</span>'}
      </div>
      <p class="claim small">${esc(text.head)}</p>
      ${evidenceToggle({
        lines: u.evidence_lines || [],
        emails: u.closed_by ? [u.closed_by] : [],
        label: 'What we have',
        detail: text.rest ? detail : '',
      })}
    </article>`;
}

/* ------------------------------------------------------------- string */

// String sags, but only into the clear band of paper below each pin. A card
// that a string runs across stops being readable, and legibility wins.
const SAG = 0.05;
const SAG_MAX = 15;

function wireStrings(container, rel) {
  const wall = container.querySelector('#wall');
  const layer = container.querySelector('#stringLayer');
  const slip = container.querySelector('#wallSlip');
  if (!wall || !layer) return;

  function anchor(key) {
    const card = wall.querySelector(`[data-ent="${key}"]`);
    if (!card) return null;
    const box = card.getBoundingClientRect();
    const base = wall.getBoundingClientRect();
    return { x: box.left - base.left + box.width / 2, y: box.top - base.top + 2 };
  }

  let drawn = false;
  function paint() {
    const base = wall.getBoundingClientRect();
    layer.setAttribute('viewBox', `0 0 ${Math.round(base.width)} ${Math.round(base.height)}`);
    layer.setAttribute('width', Math.round(base.width));
    layer.setAttribute('height', Math.round(base.height));
    const parts = [];
    rel.forEach((edge, i) => {
      const a = anchor(edge.from);
      const b = anchor(edge.to);
      if (!a || !b) return;
      const dist = Math.hypot(b.x - a.x, b.y - a.y);
      const cx = (a.x + b.x) / 2;
      // Each string hangs a little differently, so two of them tied to the
      // same pin stay telling apart.
      const cy = (a.y + b.y) / 2 + Math.min(SAG_MAX, dist * SAG) + 7 + (i % 3) * 7;
      const d = `M ${a.x} ${a.y} Q ${cx} ${cy} ${b.x} ${b.y}`;
      const ids = edge.basis.map((s) => s.id).join(', ');
      parts.push(`<g class="string conf-${esc(edge.conf)}" data-edge="${esc(edge.from)}|${esc(edge.to)}">
        <path class="string-hit" d="${d}"><title>${esc(`${edge.from} and ${edge.to}: ${ids}`)}</title></path>
        <path class="string-line" d="${d}"></path>
      </g>`);
    });
    layer.innerHTML = parts.join('');
    // Only the first paint draws itself. A resize is not a new relation.
    if (!drawn) {
      drawn = true;
      drawStrings(layer.querySelectorAll('.string-line'));
    }
  }

  paint();
  relayout = paint;
  if (window.ResizeObserver) {
    const ro = new ResizeObserver(() => paint());
    ro.observe(wall);
  } else {
    window.addEventListener('resize', paint);
  }

  layer.addEventListener('mouseover', (event) => {
    const g = event.target.closest('.string');
    if (!g) return;
    g.classList.add('lit');
    const [from, to] = g.dataset.edge.split('|');
    wall.querySelectorAll('[data-ent]').forEach((c) => {
      c.classList.toggle('lit', c.dataset.ent === from || c.dataset.ent === to);
    });
  });
  layer.addEventListener('mouseout', (event) => {
    const g = event.target.closest('.string');
    if (g) g.classList.remove('lit');
    wall.querySelectorAll('[data-ent]').forEach((c) => c.classList.remove('lit'));
  });
  layer.addEventListener('click', (event) => {
    const g = event.target.closest('.string');
    if (!g) return;
    const [from, to] = g.dataset.edge.split('|');
    const edge = rel.find((e) => e.from === from && e.to === to);
    if (!edge) return;
    slip.hidden = false;
    slip.innerHTML = `
      <div class="slip-head-row">
        <span class="tw">Why this string is here</span>
        <button class="slip-close" type="button" aria-label="Close">close</button>
      </div>
      <p class="slip-lede">${esc(from)} and ${esc(to)} are named together by ${edge.basis.length} record${edge.basis.length === 1 ? '' : 's'}.</p>
      ${edge.basis.map((s) => `
        <div class="basis">
          <div class="basis-top"><span class="card-id">${esc(s.id)}</span>${confStamp(s.conf)}</div>
          <p class="basis-text">${esc(s.text)}</p>
          ${evidenceToggle({ lines: s.lines, label: 'Raw' })}
        </div>`).join('')}`;
    slip.querySelector('.slip-close').addEventListener('click', () => { slip.hidden = true; });
    slip.scrollIntoView({ block: 'nearest' });
  });

  // The timeline is a string too: it runs from beat to beat in order.
  const strip = container.querySelector('#stripScroll');
  const stripLayer = container.querySelector('#stripLayer');
  if (strip && stripLayer) {
    const paintStrip = () => {
      const beats = Array.from(strip.querySelectorAll('.beat'));
      if (!beats.length) return;
      const base = strip.getBoundingClientRect();
      const width = strip.scrollWidth;
      const height = strip.clientHeight;
      stripLayer.setAttribute('viewBox', `0 0 ${Math.round(width)} ${Math.round(height)}`);
      stripLayer.setAttribute('width', Math.round(width));
      stripLayer.setAttribute('height', Math.round(height));
      const pts = beats.map((b) => {
        const box = b.getBoundingClientRect();
        return { x: box.left - base.left + strip.scrollLeft + box.width / 2, y: box.top - base.top + 3 };
      });
      let d = `M ${pts[0].x} ${pts[0].y}`;
      for (let i = 1; i < pts.length; i += 1) {
        const a = pts[i - 1];
        const b = pts[i];
        d += ` Q ${(a.x + b.x) / 2} ${(a.y + b.y) / 2 + 13} ${b.x} ${b.y}`;
      }
      stripLayer.innerHTML = `<path class="string-line thread" d="${d}"></path>`;
    };
    paintStrip();
    const previous = relayout;
    relayout = () => { previous(); paintStrip(); };
    if (window.ResizeObserver) new ResizeObserver(paintStrip).observe(strip);
  }
}
