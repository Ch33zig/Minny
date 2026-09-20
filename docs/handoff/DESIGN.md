# Visual design

Owner: D. Applies to everything under `dist/`. This file is the reference. Where it and an older screenshot disagree, this file wins.

**This replaces the dark monochrome instrument direction.** That version was legible and forgettable. The challenge is called Log & Order, design and wow factor are judged, and a detective's case board is both more memorable and easier to read at a glance than a dense panel of text.

## The metaphor, and the one rule that protects it

The screen is a detective's board: aged paper, kraft folders, index cards pinned to cork, photographs held down with tape, red string running between suspects, rubber stamps.

**The evidence underneath has to stay real.** Every card on the board resolves to actual log lines by line number. The theme is the presentation layer over a working forensics tool, never a decoration pretending to be one. If a choice makes it look more like a case board but less true, the choice loses. A judge who pulls a thread must find a real record at the end of it.

The second rule follows from the first: **low text, high artifact.** A wall of paragraphs is what we are replacing. A claim is one short line on a card. The detail lives behind the card, revealed when someone pulls the evidence. Numbers are large and typeset, not buried in a sentence.

## Palette

Warm, aged, printed. No pure black and no pure white anywhere.

```css
:root {
  --board:      #4A3B2C;  /* cork board, the surface everything pins to */
  --board-dark: #3A2D21;  /* vignette, deep shadow */
  --paper:      #F2E8D5;  /* index card, report page */
  --paper-2:    #E6D8BE;  /* manila folder, secondary card */
  --kraft:      #C9A87C;  /* envelope, tab, folder edge */
  --tape:       #D9CBA3;  /* masking tape, translucent */

  --ink:        #2E241C;  /* typed text */
  --ink-2:      #5B4A3A;  /* secondary typed text */
  --ink-3:      #8A7660;  /* faded carbon copy, metadata */
  --pencil:     #3F5166;  /* handwritten annotation, blue-grey pencil */

  --stamp:      #B4342A;  /* the one accent, see below */
  --stamp-dim:  #8E5A52;  /* stamp at low emphasis, string, pin shadow */
}
```

**The accent rule survives the reskin unchanged.** `--stamp` red means "this is the finding": the attacker, high severity, the CONFIDENTIAL mark, the red string. It never appears on navigation, folder tabs, buttons or body text. If red shows up in four places on one screen it has stopped meaning anything. Everything else is separated by paper tone, tape, pin, stamp and handwriting, not by hue.

| Distinction | How |
|---|---|
| Confidence high / medium / low | Stamp: `CONFIRMED` solid, `PROBABLE` outlined, `UNVERIFIED` faint and rotated |
| Severity | Red string and a red pin for high, brass pin otherwise |
| Synthetic incident | A `SIMULATION` stamp in blue-grey pencil, never red, so it cannot be confused with a finding |
| Cleared lead | A `CLEARED` stamp across the card, card desaturated and slightly rotated away |
| Mailbox corroboration | A smaller slip of paper taped on at an angle, visibly a different document |

## Type

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Special+Elite&family=Courier+Prime:wght@400;700&family=Caveat:wght@500;700&display=swap" rel="stylesheet">
```

Three faces, each with one job. Do not add a fourth.

**Special Elite** for the case title, section headers, stamps and folder tabs. A worn typewriter face. Uppercase, letterspaced `0.06em`. It carries the theme, so it appears on labels and never in a paragraph.

**Courier Prime** for everything typed: claims, body, table data, and raw log lines. This is a case file, so everything in it was typed. It is monospace, which means the raw evidence needs no separate face and log columns align for free. 400 for body, 700 for numbers and emphasis.

**Caveat** for handwriting only: margin annotations, the investigator's asides, a checkmark note beside a cleared lead, the number scrawled next to a stat. Set in `--pencil`. Handwriting is how the board says something a typed report would need a sentence for, so use it to remove text, not to add it.

| Role | Face | Size | Notes |
|---|---|---|---|
| Case title | Special Elite | 30px | upper, letterspaced |
| Section header / folder tab | Special Elite | 13px | upper, `0.1em` |
| Stamp | Special Elite | 11 to 22px | upper, rotated 2 to 6 degrees |
| Card claim | Courier Prime 700 | 15px | one line, two at most |
| Body, table | Courier Prime 400 | 13px | |
| Big stat | Courier Prime 700 | 30px | the number does the talking |
| Raw log line | Courier Prime 400 | 12px | on white paper, scrolls sideways |
| Annotation | Caveat 500 | 16px | pencil, slightly rotated |

## Textures and props, all CSS, no image files

There is no build step and no asset pipeline, so everything is generated. Keep it that way: an inline SVG filter or a gradient, never a downloaded texture.

- **Paper grain:** an inline `feTurbulence` SVG as a data URI at low opacity over `--paper`. One filter, reused.
- **Cork board:** `--board` with a fine multi-stop radial speckle and a strong inset vignette so the edges fall away.
- **Tape:** a rotated rectangle in `--tape` at about 0.8 alpha, ragged short edges via `clip-path`, a soft shadow beneath. Two per card at opposing corners, each rotated a different amount.
- **Push pin:** a small radial-gradient circle with a highlight and a cast shadow. Brass by default, `--stamp` red for the attacker and high severity.
- **Red string:** inline SVG paths between pinned cards, `--stamp` at 0.7, 1.5px, with a slight sag on the curve. Only between things genuinely linked: attacker to vector to asset to victim. **Never draw a string that does not represent a real relation in the data.**
- **Stamp:** Special Elite uppercase, 2px border in the stamp colour, rotated, roughened by a mask, at 0.85 alpha so the paper shows through.
- **Card rotation:** each card rotates between -1.5 and +1.5 degrees, derived from its own id so it is stable across renders rather than jittering on every repaint.

Every card gets a real drop shadow. Things sit on the board, they are not drawn on it.

## The five views

**Case file, the hero.** A cork board. Suspect cards top left as photographs with tape and a pin, monogram in place of a face, name in Special Elite, role stamp, and two or three big numbers. Red string runs from the attacker through the vector to the asset. Findings are index cards pinned in a loose column, each showing one short claim, a stamp for confidence, and a paper-clip affordance that opens the raw log lines as a photocopy slip. Timeline is a strip of small dated cards along the bottom, connected by string. Verdict is a typed report page, slightly larger, with a `CASE CLOSED` stamp across the corner. Cleared leads are a separate pinned cluster, desaturated, each with a `CLEARED` stamp and a pencil note.

**Live monitor.** The board as it assembles. New evidence cards pin themselves on as alerts arrive, string draws between them when the correlator links them, and the incident card grows. This is the one animation worth real effort.

**Judge's panel.** A form as a typed evidence request slip, with a stamp on submit.

**Metrics.** A pinned report page with typed tables. Numbers large. The per-operator table is the artifact, give it room.

**Blue agent.** Two memos side by side, one stamped `ACCEPTED`, one stamped `REJECTED`, with the gate results as a typed checklist and red pencil through the failed line.

## Motion

Use **Motion** (motion.dev), vanilla, already loaded in `dist/js/motion.js` from `https://cdn.jsdelivr.net/npm/motion@11/+esm`. Framer Motion needs React, which this project does not have.

Five things move, and nothing else:

1. **A card pins onto the board** when an alert arrives: drops in 8px with a slight overshoot and settles at its resting rotation. Spring, roughly `stiffness 220, damping 26`.
2. **Red string draws** between two cards when the correlator links them: `stroke-dashoffset` over 260ms.
3. **Evidence opens**: the photocopy slip unfolds, height over 180ms. It happens constantly during the demo, so it must feel instant rather than impressive.
4. **A stamp lands** once when a verdict or a gate result first renders: scale from 1.15 with a short settle, 200ms, no bounce. Once only, never on hover.
5. **View change**: a 140ms crossfade.

No parallax, no page-load choreography, no ambient drift, no animated counters. Hover may lift a card 1px and deepen its shadow, nothing more. Honour `prefers-reduced-motion: reduce` by dropping to opacity or to nothing.

## Legibility, which outranks the theme

The texture is background, never behind running text at low contrast. Typed ink on paper must stay at 4.5:1 or better. Rotation stays under 2 degrees on anything containing a sentence. Raw log lines sit on the flattest, cleanest paper on the board with no grain behind them, because that block is the proof and it has to be readable without effort.

It has to work at 1280x720 on a projector, where contrast is worse than a laptop and the back row is far away. If a prop hurts reading, cut the prop.
