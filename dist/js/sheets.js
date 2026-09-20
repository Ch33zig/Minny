// A case folder is flipped, not scrolled.
//
// Every long view on this board is cut into sheets, one screen each, and the
// viewer steps between them with the flip controls or the arrow keys. Nothing
// inside a sheet is restyled: the same sections that used to sit in one very
// tall column are simply not all on the wall at once.
//
// Usage:  container.innerHTML = sheaf([{ name: 'The board', html }, ...]);
//         const book = mountSheets(container, () => repaint());
//         book.show(2);

import { esc } from './dom.js';
import { crossfadeView } from './motion.js';

const books = new WeakMap();

/** Wrap sections as sheets behind one set of flip controls. */
export function sheaf(sheets) {
  const tabs = sheets.map((s, i) => `
    <button class="exhibit-dot${i ? '' : ' on'}" type="button" data-go="${i}"
            title="${esc(s.name)}" aria-label="Exhibit ${i + 1}, ${esc(s.name)}"></button>`).join('');
  return `
    <div class="sheaf" data-sheaf>
      <nav class="sheaf-nav" aria-label="Exhibits">
        <button class="flip" type="button" data-step="-1" aria-label="Previous exhibit">
          <span class="flip-arrow">&#9664;</span><span class="flip-word">Back</span>
        </button>
        <div class="exhibit">
          <span class="exhibit-no">Exhibit <b class="exhibit-i">1</b> of ${sheets.length}</span>
          <span class="exhibit-name" data-exhibit-name>${esc(sheets[0] ? sheets[0].name : '')}</span>
          <span class="exhibit-dots">${tabs}</span>
        </div>
        <button class="flip" type="button" data-step="1" aria-label="Next exhibit">
          <span class="flip-word">Next</span><span class="flip-arrow">&#9654;</span>
        </button>
      </nav>
      <div class="sheets">
        ${sheets.map((s, i) => `
          <section class="sheet" data-sheet="${i}" data-name="${esc(s.name)}"${i ? ' hidden' : ''}>${s.html}</section>`).join('')}
      </div>
    </div>`;
}

/**
 * Wire the flip controls. `onShow(index, sheet)` runs after each step, which is
 * where a view repaints anything it had to measure on screen.
 */
export function mountSheets(container, onShow) {
  const root = container.querySelector('[data-sheaf]');
  if (!root) return null;
  const sheets = Array.from(root.querySelectorAll('.sheet'));
  const label = root.querySelector('[data-exhibit-name]');
  const counter = root.querySelector('.exhibit-i');
  const dots = Array.from(root.querySelectorAll('.exhibit-dot'));
  let at = 0;

  function show(index, { animate = true } = {}) {
    if (!sheets.length) return;
    const next = ((index % sheets.length) + sheets.length) % sheets.length;
    const changed = next !== at;
    at = next;
    sheets.forEach((s, i) => { s.hidden = i !== at; });
    dots.forEach((d, i) => d.classList.toggle('on', i === at));
    if (counter) counter.textContent = String(at + 1);
    if (label) label.textContent = sheets[at].dataset.name || '';
    // The motion list allows a crossfade between views. A sheet is a view.
    if (changed && animate) crossfadeView(sheets[at]);
    if (onShow) onShow(at, sheets[at]);
  }

  const book = {
    show,
    step: (delta) => show(at + delta),
    count: sheets.length,
    at: () => at,
    /** The sheet a node sits on, or -1 when it is not on any of them. */
    sheetOf: (node) => sheets.findIndex((s) => s.contains(node)),
  };
  books.set(container, book);

  root.addEventListener('click', (event) => {
    const step = event.target.closest('[data-step]');
    if (step) return book.step(Number(step.dataset.step));
    const go = event.target.closest('[data-go]');
    if (go) book.show(Number(go.dataset.go));
  });

  show(0, { animate: false });
  return book;
}

/** The sheets of a mounted view, for the keyboard handler in main.js. */
export function sheetsOf(container) {
  return books.get(container) || null;
}
