// Motion (motion.dev), the vanilla successor to Framer Motion. Framer Motion
// proper needs React, and this project deliberately has neither React nor a
// build step, so the library is pulled in as an ES module from a CDN.
//
// Five things move on this board and nothing else does:
//
//   pinCard         a card drops 10px onto the cork and settles at its resting
//                   angle. Spring, because a pin is a physical event.
//   drawStrings     red string draws itself between two cards the moment the
//                   data links them. 260ms of stroke-dashoffset.
//   expandEvidence  a claim opens onto its raw bytes. 180ms, because it happens
//                   on nearly every click and has to feel instant, not clever.
//   layStamp        a stamp lands once, on a verdict or a gate result. 200ms
//                   from 1.15 with no bounce, and never on hover.
//   crossfadeView   140ms between views. Nothing slides.
//
// growIncident is the same pin, applied to a card that is getting taller: the
// product's whole argument is that twenty warnings are one story.
//
// The import is deliberately not awaited at the top level. The fixture demo is
// the parachute when the backend dies and it has to survive a dead network too,
// so every helper falls back to doing nothing and the caller is always left
// holding the final state.

const CDN = 'https://cdn.jsdelivr.net/npm/motion@11/+esm';

let animate = null;
let stagger = null;

window.__minnyMotion = 'loading';
import(CDN)
  .then((motion) => {
    animate = motion.animate;
    stagger = motion.stagger;
    window.__minnyMotion = 'loaded';
  })
  .catch(() => { window.__minnyMotion = 'unavailable'; });

// A judge may be on a machine with reduced motion set. Everything below then
// drops to an opacity change or to nothing at all.
const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
const off = () => !animate || reduced.matches;

/** Motion 11 hands back a thenable; older builds hand back `.finished`. */
function done(controls) {
  if (!controls) return Promise.resolve();
  return Promise.resolve(controls.finished || controls).catch(() => {});
}

/* -------------------------------------------------------------- view change */

export function crossfadeView(node) {
  // Opacity only, which is what reduced motion would have asked for anyway.
  if (!animate || !node) return;
  animate(node, { opacity: [0, 1] }, { duration: 0.14, ease: 'easeOut' });
}

/* ----------------------------------------------------------- evidence block */

/** Open from nothing to the block's natural height. */
export function expandEvidence(body) {
  if (!body) return;
  if (off()) return;
  const end = body.scrollHeight;
  if (!end) return;
  body.style.overflow = 'hidden';
  done(animate(body, { height: ['0px', `${end}px`] }, { duration: 0.18, ease: 'easeOut' }))
    .then(() => { body.style.height = ''; body.style.overflow = ''; });
}

/** The loading line is replaced by the real bytes: grow from one to the other. */
export function resizeEvidence(body, from) {
  if (!body) return;
  if (off()) return;
  const end = body.scrollHeight;
  if (!end || Math.abs(end - from) < 2) return;
  body.style.overflow = 'hidden';
  done(animate(body, { height: [`${from}px`, `${end}px`] }, { duration: 0.18, ease: 'easeOut' }))
    .then(() => { body.style.height = ''; body.style.overflow = ''; });
}

/** Close again. Resolves once the block is safe to hide. */
export function collapseEvidence(body) {
  if (!body || off()) return Promise.resolve();
  const from = body.getBoundingClientRect().height;
  if (!from) return Promise.resolve();
  body.style.overflow = 'hidden';
  return done(animate(body, { height: [`${from}px`, '0px'] }, { duration: 0.18, ease: 'easeIn' }))
    .then(() => { body.style.height = ''; body.style.overflow = ''; });
}

/* ------------------------------------------------------------- ticker rows */

// Rows arrive one call at a time but often many to a frame, so they are
// collected and released together. That is what makes stagger mean anything.
let pending = [];
let queued = 0;

export function enterRow(node) {
  if (!node || off()) return;
  node.style.opacity = '0';
  pending.push(node);
  if (queued) return;
  queued = requestAnimationFrame(() => {
    const rows = pending;
    pending = [];
    queued = 0;
    rows.forEach((row) => { row.style.opacity = ''; });
    animate(rows, { opacity: [0, 1], y: [6, 0] }, { duration: 0.18, delay: stagger(0.02), ease: 'easeOut' });
  });
}

/* ----------------------------------------------------------- incident cards */

/**
 * The one animation worth spending effort on. The card has already been given
 * its new content, so `from` and `to` are measured either side of that swap and
 * the card springs between them while the new narrative beats fade in.
 */
export function growIncident(node, from, to, fresh = []) {
  if (!node || !animate) return;
  if (reduced.matches) {
    if (fresh.length) animate(fresh, { opacity: [0, 1] }, { duration: 0.14 });
    return;
  }
  if (fresh.length) {
    animate(fresh, { opacity: [0, 1], y: [6, 0] }, { duration: 0.3, delay: stagger(0.05), ease: 'easeOut' });
  }
  if (!from || Math.abs(to - from) < 2) return;
  node.style.overflow = 'hidden';
  done(animate(node, { height: [`${from}px`, `${to}px`] }, { type: 'spring', stiffness: 220, damping: 28 }))
    .then(() => { node.style.height = ''; node.style.overflow = ''; });
}

/** A card appearing for the first time has no height to grow from. */
export function bornIncident(node) {
  if (!node || !animate) return;
  if (reduced.matches) {
    animate(node, { opacity: [0, 1] }, { duration: 0.14 });
    return;
  }
  const to = node.getBoundingClientRect().height;
  node.style.overflow = 'hidden';
  animate(node, { opacity: [0, 1] }, { duration: 0.2, ease: 'easeOut' });
  done(animate(node, { height: ['0px', `${to}px`] }, { type: 'spring', stiffness: 220, damping: 28 }))
    .then(() => { node.style.height = ''; node.style.overflow = ''; });
}

/* ------------------------------------------------------------ board props */

/** The angle a node is already resting at, read off its computed matrix. */
function currentRotation(node) {
  const t = getComputedStyle(node).transform;
  const m = t && t !== 'none' && t.match(/matrix\(([^)]+)\)/);
  if (!m) return 0;
  const [a, b] = m[1].split(',').map(Number);
  return (Math.atan2(b, a) * 180) / Math.PI;
}

/**
 * A card pins onto the board: drops in with a little overshoot and settles at
 * the resting rotation its id gave it. Called when a card arrives, never on a
 * view that was already there.
 */
export function pinCard(node) {
  if (!node || !animate) return;
  const rest = currentRotation(node);
  if (reduced.matches) {
    animate(node, { opacity: [0, 1] }, { duration: 0.14 });
    return;
  }
  animate(node, { opacity: [0, 1] }, { duration: 0.16, ease: 'easeOut' });
  animate(
    node,
    { y: [-10, 0], rotate: [rest * 0.25, rest] },
    { type: 'spring', stiffness: 220, damping: 26 },
  );
}

/** Red string draws between two cards the data has linked. */
export function drawStrings(paths) {
  const list = Array.from(paths || []);
  if (!list.length || !animate || reduced.matches) return;
  for (const path of list) {
    const len = typeof path.getTotalLength === 'function' ? path.getTotalLength() : 0;
    if (!len) continue;
    path.style.strokeDasharray = String(len);
    done(animate(path, { strokeDashoffset: [len, 0] }, { duration: 0.26, ease: 'easeOut' }))
      .then(() => { path.style.strokeDasharray = ''; path.style.strokeDashoffset = ''; });
  }
}

/** A stamp lands. Once, on first render, with no bounce. */
export function layStamp(node) {
  if (!node || !animate) return;
  if (reduced.matches) {
    animate(node, { opacity: [0, 1] }, { duration: 0.14 });
    return;
  }
  const rest = currentRotation(node);
  animate(node, { opacity: [0, 1] }, { duration: 0.12 });
  animate(node, { scale: [1.15, 1], rotate: [rest, rest] }, { duration: 0.2, ease: [0.3, 0.9, 0.4, 1] });
}
