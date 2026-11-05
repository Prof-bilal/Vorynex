# LANDING_DESIGN.md — benchmark research and landing spec

How the Vorynex landing page is designed, and the evidence behind it. Captured
by rendering each reference at 1440×900 with headless Chromium and reading the
screenshots, so these are observations of the real pages, not memory.

## 1. What the references actually do

| | Nav | Hero headline | Hero CTAs | Product visual | Background |
|---|---|---|---|---|---|
| **Linear** | 6 muted links, divider, `Log in` text + white pill `Sign up` | ~72–84px, weight 500–600, tracking ≈ −0.03em, **flat solid white**, 2 lines, left-aligned | none in-hero (nav pill is the CTA) | one large app window, ~12–16px radius, 1px border rgba(255,255,255,.08), elevated on `#0B0C0E`; a floating "agent" card overlaps it for depth | flat `#08090A` — **no gradient, no glow, no grid** |
| **Vercel** | 4 links w/ chevrons + 3 pill buttons (black fill = primary) | ~80–90px, medium/semibold, tracking ≈ −0.03em, pure `#000`, 2 lines, left gutter | `Deploy now` (solid) + `Talk to sales` (outline) | **none** — type only | flat `#fff`, poster-like negative space, then a monochrome logo strip |
| **Cloudflare** | logo + 3 dropdowns + `Pricing`, `Under attack?` link, `Login`, `Contact sales` | ~64–72px, centered, tight leading 1.0–1.05 | one white pill on an orange field | **none in hero** — type + texture | full-bleed orange card, warm radial glow bottom-center, fine **dot-lattice texture** |
| **Tailscale** | announcement bar → nav with `+` dropdowns, `Login` + white `Get started – it's free!` | ~72–80px, weight ~500, tracking ≈ −0.02em, leading ≈ 1.05, centered | `Start connecting devices` (solid) + `Contact sales` (text link) | **none in hero**; a 5-card feature row below with one accent-filled card | flat light; **one accent colour** (dark red) carries the only emphasis |

### The patterns that repeat (these are the "premium" tells)

1. **Type-led heroes.** Not one of the four uses stock photos, 3D art, or a
   dashboard screenshot in the hero. The headline *is* the artwork: 64–90px,
   weight 500–600 (never 700+), tracking between −0.02 and −0.04em, leading ≈ 1.0.
2. **One primary action.** Solid filled button = primary; everything else is a
   border pill or a plain text link. Cloudflare and Tailscale hero CTAs have
   *no* secondary button at all.
3. **Restraint in the background.** Flat colour, or at most *one* radial glow
   and *one* subtle texture (Cloudflare's dot lattice). Nobody stacks
   gradient + grid + noise + glow.
4. **Cards get explicit elevation.** Linear's app window is readable because of
   three cheap things: a 1px border at ~8% white, a slightly lighter surface
   than the page, and a soft diffuse shadow. No neon.
5. **Exactly one accent hue**, used on a small number of elements. Everything
   else is a grey ramp.
6. **A quiet logo/social strip** directly under the hero (Vercel: six mono
   logos evenly spread; Linear: "powering 50,000 teams").
7. **Left-aligned or centred, never mixed.** Linear/Vercel left; Cloudflare/
   Tailscale centred. The composition is consistent inside one page.

## 2. Critique of the page we had

Benchmarked against the above, the first Next.js landing had these problems,
ordered by damage:

1. **The showcase card was cropped mid-row at the fold** — "PostgreSQL" and a
   second `CONTAINED` item sliced in half. It read as an unfinished build, and
   it was the strongest trust signal on the page.
2. **Duplicate CTAs.** `Sign in` + `Get started` in the nav, then
   `Get started free` + `See how it works` in the hero. Template smell.
3. **Headline break was wrong** — "Vorynex makes exploiting / them a dead end"
   orphaned the payoff, and 3 stacked lines read as three sentences.
4. **Grey gradient fade on the headline** — the last line lost contrast and
   looked disabled. The stock "gradient text" trick.
5. **Product card had no elevation** — no top highlight, no glow, no shadow, so
   it barely separated from the page.
6. **Subhead too long and too close in weight** to the headline; the bolded
   clause was doing hierarchy work that size should do.
7. **No brand accent.** The only saturated pixels were semantic (amber/red/green),
   so the page could have been any security startup.
8. **Equal spacing steps** (eyebrow → h1 → sub → CTA all ~the same gap), so the
   eye had no grouping.
9. **"Runs on" chips** carried the visual weight of a real logo strip but
   conveyed nothing.
10. **Inconsistent in-card type** — the trace data (the actual evidence) was the
    smallest, dimmest thing in the card.

## 3. The spec we now build to

### Tokens

```
--bg        #08090a      --surface   #0e0f11     --sunken   #121316
--ink       #f7f8f8      --ink-2     #a8adb5     --ink-3    #6f747c
--line      rgba(255,255,255,.08)    --line-2 rgba(255,255,255,.15)
--accent    #5eead4   (structural only: markers, links, focus, card top edge)
--denied    #ff8677   (semantic only — never decorative)
--ok        #83bd9f   (semantic only)
--warn      #e0b06a   (semantic only)
```

Three hues maximum on any screen: the grey ramp, plus `--accent`, plus at most
one semantic colour inside the product UI.

### Type scale

| Role | Size | Weight | Tracking | Leading |
|---|---|---|---|---|
| Display (hero h1) | `clamp(40px, 5.6vw, 72px)` | 600 | −0.035em | 1.03 |
| Section h2 | `clamp(28px, 3.2vw, 40px)` | 600 | −0.03em | 1.1 |
| Card h3 | 18px | 600 | −0.015em | 1.35 |
| Lede | 17px | 400 | 0 | 1.65 |
| Body | 14.5px | 400 | 0 | 1.6 |
| Kicker / micro | 11.5px uppercase | 600 | 0.14em | 1.4 |
| Mono (evidence) | 12.5–13px | 400–500 | 0 | 1.5 |

Rules: **no gradient text**. Headline is solid `--ink`; the punchline may be
`--accent` or stay white. Body copy never below 14.5px; the *evidence* in cards
is the largest mono on the page, not the smallest.

### Spacing rhythm (4px base)

`4 · 8 · 12 · 16 · 24 · 32 · 48 · 64 · 96 · 112`

Hero: eyebrow →16→ h1 →24→ lede →28→ CTAs →56→ showcase.
Section: `padding-block 112px`, kicker →12→ h2 →16→ lede →40→ content.
Never two equal consecutive gaps — grouping must be visible.

### Components

- **Nav**: logo, 4 links, one text link (`Sign in`), **one** primary pill.
- **Hero**: centred, 2-line headline, ≤ 2-line lede, primary + ghost CTA, then a
  quiet platform line (not chips).
- **Showcase**: a *self-contained* panel that fits the fold — browser chrome,
  5 trace hops, 2-column blast radius with 3 items each — with a 1px border, a
  lighter surface, a soft shadow and a top edge highlight. Bottom fades with a
  mask so any crop is deliberate, never mid-row.
- **Runs-on strip**: micro label + evenly distributed monospace items, no pills.
- **Bento features**: one wide cell with a mini visual + four small cells with
  thin line icons (Tailscale's 5-card row, Cloudflare's grid).
- **Steps**: numbered, each with a real command.
- **FAQ**: native `<details>`, one accent rule on the open item.
- **Footer**: minimal, two columns.

### Verification loop

Every iteration is rendered with
`chromium --headless=new --window-size=1440,900 --screenshot=…` and read back,
and the critique list above is re-checked. A change is only done when the
screenshot shows it.

**Measure, don't guess.** `--window-size=1440,900` yields a **757px content
viewport** (the rest is window furniture), which silently invalidated the first
two rounds of pixel math: the card looked "cut off" because it was being judged
against a fold 143px shorter than assumed. Geometry is now read from the live
page over the DevTools protocol (`.nav`, `h1`, `.showcase`, `.pane-foot`, … all
`getBoundingClientRect()`), so fixes land with numbers rather than eyeballing.

Final measured hero at 1440×757:

| Element | top | bottom |
|---|---|---|
| nav | 0 | 63 |
| eyebrow | 93 | 123 |
| h1 (2 lines, 46px) | 137 | 234 |
| lede (2 lines) | 248 | 301 |
| deny pills | 319 | 348 |
| CTAs | 374 | 419 |
| showcase | 451 | **730** (fits, 27px clearance) |

## 4. Result

Independent review of the rendered page against the same four references scored
the hero **9/10** and "ship it", after three measured rounds that fixed: a
4-line headline (now 2), duplicate CTA labels, a card clipped by the fold, an
amber-tinted pill set, invisible elevation, and dim in-card metadata.

Semantic colour finally reads as a triad rather than decoration:
**teal** = the single structural accent (marker, top hairline, glow),
**amber** = reachable, **vermilion** = denied, **pine** = contained.

Dashboard follow-ups from the same review: the event list is capped at 10 rows
instead of running off the fold, repeated timestamps are collapsed, `miss` now
uses the warn tone so failures out-rank `allowed`, and the low-contrast mono
(hash, timestamps) was raised to `#9aa1ab`.

