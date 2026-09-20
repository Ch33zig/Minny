# Visual design

Owner: D. Applies to everything under `dist/`. This file is the reference; where it and an older screenshot disagree, this file wins.

The product is a forensics tool. It should read like an instrument, not a dashboard. Restraint is the brief: near monochrome, one accent used sparingly enough that it still means something, and motion only where it carries information.

## Palette

Dark only. There is no light theme and nothing should be written to support one.

```css
:root {
  --bg:        #0B0B0C;  /* page */
  --surface:   #141416;  /* cards, panels */
  --surface-2: #1C1C1F;  /* raised rows, inputs, evidence blocks */
  --line:      #2A2A2E;  /* hairlines, card borders */
  --line-2:    #3A3A40;  /* emphasised borders */

  --text:      #EDEDEF;  /* primary */
  --text-2:    #A1A1A8;  /* secondary, labels, table body */
  --text-3:    #6E6E76;  /* tertiary, timestamps, muted metadata */

  --accent:    #E8A33D;  /* amber. see the rule below */
  --accent-dim:#5A4423;  /* amber at low emphasis, for borders and rails */
}
```

**The accent rule: amber means "this is the finding".** Reserve it for high severity and for the attacker. It must not appear on navigation, headings, buttons, focus rings, links, charts, or anything decorative. If amber shows up in three places on one screen it has stopped carrying meaning. A screen where nothing is high severity should be entirely greyscale, and that is correct, not unfinished.

Everything else that needs to be distinguished is distinguished without hue:

| Distinction | How |
|---|---|
| Severity high / medium / low | Amber rail for high. Medium and low use `--text` and `--text-2` on a plain border |
| Confidence high / medium / low | Border style: solid, dashed, dotted. Works in greyscale and survives a projector |
| Synthetic vs real incident | Hatched grey border plus a `SYNTHETIC` label in Doto. Never amber, or it competes with severity |
| Corroborating mailbox evidence | Dashed hairline and `--text-3`, set below the log block, never beside it |

## Type

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Doto:wght@400;700;900&family=Barlow+Semi+Condensed:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
```

**Doto**, uppercase, for large text with few words. View titles, the verdict headline, big metric numbers, section labels. It is a dot matrix face: it reads as instrumentation at size and becomes illegible small. Never below 18px, never for a sentence, never for body copy. Letterspace it (`0.08em` at display sizes, `0.14em` for small caps labels) because the dot grid needs air.

**Barlow Semi Condensed** for everything a person actually reads. Narrative, findings, table text, controls, buttons, help text. 400 for body, 500 for table headers, 600 for emphasis, 700 only where something must be found at a glance. Its condensed width is doing real work here: the case file is dense and this fits more evidence per column without shrinking the type.

**JetBrains Mono** for raw log lines and nothing else. Evidence must align by column and must look unmistakably like a file rather than like prose. 400 weight, 12.5px, `--text-2` on `--surface-2`.

Scale:

| Role | Face | Size | Weight | Case |
|---|---|---|---|---|
| View title | Doto | 34px | 700 | upper |
| Verdict headline | Doto | 26px | 700 | upper |
| Metric figure | Doto | 40px | 900 | upper |
| Section label | Doto | 11px | 400 | upper, `0.14em` |
| Card title | Barlow SC | 17px | 600 | sentence |
| Body | Barlow SC | 14.5px | 400 | sentence |
| Table | Barlow SC | 13.5px | 400 | sentence |
| Metadata | Barlow SC | 12px | 500 | upper, `0.06em` |
| Evidence | JetBrains Mono | 12.5px | 400 | as written |

## Motion

Use **Motion** (motion.dev), the vanilla successor to Framer Motion. Framer Motion proper requires React and we do not have React. The vanilla API has the same spring engine and loads from a CDN with no build step:

```js
import { animate, stagger, inView } from "https://cdn.jsdelivr.net/npm/motion@11/+esm";
```

Motion is for conveying change, not for decoration. Four places earn it:

1. **Incident card growth.** When a correlated alert lands, spring the card height and fade the new narrative beat in. This animation *is* the product's core idea, that twenty warnings become one story, so it is the one place to spend real effort. Spring, roughly `stiffness 220, damping 28`.
2. **Evidence expand.** Height auto with a 180ms ease. It happens constantly during the demo, so it must feel instant rather than impressive.
3. **Ticker rows.** New rows enter with a 6px rise and a fade, `stagger(0.02)`. Subtle enough to read as flow.
4. **View change.** A 140ms crossfade. Nothing sliding.

Everything else stays still. Specifically:

- **Hover:** at most a border lightening from `--line` to `--line-2`, or a background step to `--surface-2`. No scale, no lift, no shadow, no glow, no colour change on hover anywhere.
- No parallax, no entrance animations on page load, no animated counters on the metrics panel, no looping or ambient motion.
- Honour `prefers-reduced-motion: reduce` by dropping every animation to an opacity change or to nothing. A judge may be on a machine with it set.

## Layout

Unchanged from what is built: four internally scrolling columns on the case file, verdict and both suspect cards above the fold at 1280x720. Keep it working at 1280x600.

Hairlines not shadows. Borders are `1px solid var(--line)`. Corner radius 4px, or 0 on evidence blocks so they read as raw output. Generous vertical rhythm, tight horizontal, which is what the condensed face is for.
