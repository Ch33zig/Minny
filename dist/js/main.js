import { api, mode } from './api.js';
import { $, $$, esc, fmtDate, fmtNum, NONE, toast } from './dom.js';
import { toggleAll } from './evidence.js';
import { crossfadeView } from './motion.js';
import * as caseView from './views/casefile.js';
import * as monitorView from './views/monitor.js';
import * as judgeView from './views/judge.js';
import * as metricsView from './views/metrics.js';
import * as blueView from './views/blue.js';

const VIEWS = {
  case: { module: caseView, title: 'Case file' },
  monitor: { module: monitorView, title: 'Live monitor' },
  judge: { module: judgeView, title: "Judge's panel" },
  metrics: { module: metricsView, title: 'Evaluation metrics' },
  blue: { module: blueView, title: 'Blue agent' },
};
const ORDER = Object.keys(VIEWS);

let current = null;

/** The one-click parachute: same page, same view, reading fixtures. */
function mockHref() {
  const url = new URL(location.href);
  url.searchParams.set('mock', '1');
  return url.pathname + url.search + url.hash;
}

function setMode() {
  const chip = $('#modeChip');
  chip.textContent = mode.label;
  chip.classList.toggle('mock', mode.mock);
  chip.title = `Reading from ${mode.source}`;
}

async function setHeader() {
  try {
    const cf = await api.caseFile();
    $('#caseId').textContent = (cf.case_id || 'minny').toUpperCase();
    $('#caseTitle').textContent = cf.title || 'Case file';
    if (cf.window) {
      $('#windowChip').textContent = `${fmtDate(cf.window.start)} to ${fmtDate(cf.window.end)}`;
      $('#windowChip').hidden = false;
    }
    if (cf.source) {
      $('#srcLines').textContent = `${fmtNum(cf.source.lines)} lines`;
      $('#srcHash').textContent = String(cf.source.sha256 || '').slice(0, 12) || NONE;
      $('#srcHash').title = cf.source.sha256 || '';
    }
    document.title = `Minny · ${cf.title}`;
  } catch (err) {
    $('#caseTitle').textContent = 'Case file unavailable';
    $('#caseId').textContent = 'MINNY';
    $('#windowChip').hidden = true;
    toast(`Case file did not load: ${err.message}. Try ?mock=1.`, 'bad');
  }
}

async function show(name) {
  if (!VIEWS[name]) name = 'case';
  if (current === name) return;
  const previous = current && VIEWS[current].module;
  if (previous && previous.leave) previous.leave();
  current = name;

  $('#viewTitle').textContent = VIEWS[name].title;
  $$('#nav .tab').forEach((a) => {
    const on = a.dataset.view === name;
    a.classList.toggle('active', on);
    if (on) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
  $$('.view').forEach((v) => { v.hidden = v.id !== `view-${name}`; });

  const container = $(`#view-${name}`);
  const view = VIEWS[name].module;
  if (container.dataset.rendered !== '1') {
    container.innerHTML = '<div class="loading">opening the file…</div>';
    try {
      await view.render(container);
      container.dataset.rendered = '1';
    } catch (err) {
      container.innerHTML = `<div class="paper pinned fail-note" style="--rot:-0.6deg">
        <span class="pin red"></span>
        <h2 class="fail-head">${esc(VIEWS[name].title)} could not load</h2>
        <p class="fail-why">${esc(err.message)}</p>
        <p class="fail-fix">${mode.mock
          ? 'Reading from <code>' + esc(mode.source) + '</code>. Check that the fixtures directory is being served.'
          : 'The API is not answering. The fixture demo needs no backend at all.'}</p>
        ${mode.mock ? '' : `<a class="ctl primary-ctl" href="${esc(mockHref())}">Switch to fixtures</a>`}
      </div>`;
      return;
    }
  }
  crossfadeView(container);
  if (view.enter) view.enter();
}

function route() {
  show((location.hash || '#case').slice(1).split('?')[0]);
}

window.addEventListener('hashchange', route);
window.addEventListener('keydown', (event) => {
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  const tag = (event.target.tagName || '').toLowerCase();
  if (tag === 'input' || tag === 'select' || tag === 'textarea') return;
  const index = ORDER.indexOf(current);
  if (event.key >= '1' && event.key <= '5') {
    location.hash = `#${ORDER[Number(event.key) - 1]}`;
  } else if (event.key === 'e' && current === 'case') {
    const root = $('#view-case');
    const anyClosed = Array.from(root.querySelectorAll('.ev-toggle'))
      .some((b) => b.getAttribute('aria-expanded') !== 'true');
    toggleAll(root, anyClosed);
  } else if (event.key === ' ' && current === 'monitor') {
    event.preventDefault();
    monitorView.togglePlay();
  } else if (index >= 0 && (event.key === 'ArrowLeft' || event.key === 'ArrowRight')) {
    const next = (index + (event.key === 'ArrowRight' ? 1 : ORDER.length - 1)) % ORDER.length;
    location.hash = `#${ORDER[next]}`;
  }
});

setMode();
setHeader();
route();
