// Small DOM and formatting helpers. No dependencies, no build step.

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

/** Escape for interpolation into innerHTML. Raw log bytes go through this. */
export function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

export function el(tag, attrs = {}, html = '') {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else node.setAttribute(k, v === true ? '' : v);
  }
  if (html) node.innerHTML = html;
  return node;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const ISO = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?$/;

/**
 * Format an ISO timestamp in the offset it was recorded in, never the viewer's
 * local time. A forensic timeline that silently shifts by the reader's timezone
 * is worse than no timeline.
 */
export function fmtTs(iso, { withYear = false, withOffset = false } = {}) {
  if (!iso) return 'n/a';
  const m = ISO.exec(iso);
  if (!m) return iso;
  const [, y, mo, d, hh, mm, ss, off] = m;
  const day = `${Number(d)} ${MONTHS[Number(mo) - 1]}${withYear ? ' ' + y : ''}`;
  const time = `${hh}:${mm}:${ss}`;
  return `${day} ${time}${withOffset && off ? ' ' + off : ''}`;
}

export function fmtDate(iso) {
  const m = ISO.exec(iso || '');
  return m ? `${Number(m[3])} ${MONTHS[Number(m[2]) - 1]} ${m[1]}` : (iso || 'n/a');
}

export function fmtNum(n) {
  if (n === null || n === undefined) return 'n/a';
  return Number(n).toLocaleString('en-US');
}

export function fmtPct(rate) {
  if (rate === null || rate === undefined) return 'n/a';
  return `${(Number(rate) * 100).toFixed(0)}%`;
}

export function fmtBytes(n) {
  if (n === null || n === undefined) return 'n/a';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(2)} MB`;
}

/** Confidence is rendered as a visible label everywhere it appears. */
export function confChip(level, extra = '') {
  const l = (level || 'unknown').toLowerCase();
  const kind = { high: 'ARITHMETIC', medium: 'INFERRED', low: 'WEAK' }[l] || '';
  return `<span class="conf conf-${esc(l)}" title="${esc(kind)}">${esc(l)}${extra ? ` · ${esc(extra)}` : ''}</span>`;
}

export function sevChip(sev) {
  const s = (sev || 'unknown').toLowerCase();
  return `<span class="sev sev-${esc(s)}">${esc(s)}</span>`;
}

let toastTimer;
export function toast(message, kind = '') {
  const t = $('#toast');
  if (!t) return;
  t.className = `toast show ${kind}`;
  t.textContent = message;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = 'toast'; }, 4200);
}
