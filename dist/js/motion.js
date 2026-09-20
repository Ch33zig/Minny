// Motion (motion.dev), the vanilla successor to Framer Motion. Framer Motion
// proper needs React, and this project deliberately has neither React nor a
// build step, so the library is pulled in as an ES module from a CDN.
//
// Four things move on this front end and nothing else does:
//
//   growIncident    a correlated alert lands and the card springs taller. This
//                   one is the product's whole argument, that twenty warnings
//                   are one story, so it is the only place worth real effort.
//   expandEvidence  a claim opens onto its raw bytes. 180ms, because it happens
//                   on nearly every click and has to feel instant, not clever.
//   enterRows       ticker rows rise 6px and fade, staggered, so a burst of
//                   events reads as flow rather than as a redraw.
//   crossfadeView   140ms between views. Nothing slides.
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
