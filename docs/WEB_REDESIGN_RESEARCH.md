# Vorynex web redesign — research and implementation

Research date: 6 November 2026. Scope: the existing Next.js marketing site,
dashboard, workload details, settings, authentication, and recovery pages.

## Decision

Use a restrained charcoal and lime system with an application boundary as the
central visual. Explain the product with inspectable examples and progressive
detail: boundary → product preview → observe/review/enforce → local architecture
→ limitations and FAQ. The audience is developers and operators evaluating runtime
least privilege for an internet-facing application.

This is a design inference from the references below, not a claim that the
references validate Vorynex’s security or performance. No competitor metrics,
customer logos, testimonials, or performance claims are used as Vorynex evidence.

## Primary source ledger

All sources accessed 6 November 2026. Dates are included only where available.

| Source | Observation | Design implication |
| --- | --- | --- |
| [Linear: A calmer interface for a product in motion](https://linear.app/now/behind-the-latest-design-refresh), Linear, 12 March 2026 | Emphasizes consistent action placement and reducing sidebar prominence in dense interfaces. | Quiet sidebar, consistent page actions, stronger hierarchy for workload data. |
| [Wiz runtime sensor](https://www.wiz.io/solutions/runtime-sensor), Wiz, undated | Organizes runtime capabilities around workload visibility, deployment, detection, and contextual evidence. | Show the product near the top and connect fleet visibility to workload-level evidence. Do not borrow its broad platform claims. |
| [Aikido Security](https://www.aikido.dev/), Aikido, undated | Uses a concise developer-oriented value proposition and immediate product storytelling. | Start with the outcome; offer one primary action and a product exploration path. |
| [Aikido Zen for legacy apps](https://help.aikido.dev/zen-firewall/use-cases/aikido-zen-for-legacy-apps), Aikido documentation, undated | Explains an in-process security model that observes sensitive application operations. | Vorynex needs an explicit architecture illustration explaining its different local host boundary. |
| [Tetragon enforcement](https://tetragon.io/docs/concepts/enforcement/), Tetragon, undated | Documents distinct enforcement mechanisms and their operational limitations. | Present Landlock and eBPF-LSM separately, with host and tier requirements visible. |
| [Tailscale access control](https://tailscale.com/docs/features/access-control), Tailscale documentation, undated | Explains least privilege with explicit resources and policy rules. | Illustrate approved files/database alongside denied shell/secret operations, labeled as an illustrative policy. |
| [Sysdig drift detection policy](https://docs.sysdig.com/en/sysdig-secure/drift_policy/), Sysdig documentation, undated | Makes detection scope, exceptions, and blind spots explicit. | Explain baseline coverage limits and avoid universal exploit-prevention language. |
| [WCAG 2.2](https://www.w3.org/TR/WCAG22/), W3C | Defines accessibility requirements for keyboard, focus, contrast, reflow, and target sizing. | Provide skip links, visible focus, semantic controls, responsive layouts, reduced-motion support, and local table scrolling. Automated checks do not establish full conformance. |

## Repository evidence and constraints

- `web/app/page.tsx`: marketing entry point and existing authenticated CTA routing.
- `web/app/dashboard/*`: server-rendered fleet, policy, blast radius, CVE, and settings views.
- `web/app/_components/ModeControl.tsx`: existing protection mode mutations.
- `web/lib/control.ts`: server-side control plane access; never expose its token to the browser.
- `web/app/login/[[...login]]` and `signup/[[...signup]]`: existing Clerk components.
- Enforcement remains local and outside the HTTP request path. Cloud is optional.

## Design choices and tradeoffs

1. Charcoal surfaces and pale lime make the product distinct while keeping red and
   amber for denied and caution states. Consistent tokens also theme Clerk.
2. A code-native boundary diagram explains the actual architecture without stock
   hacker imagery or an additional image dependency.
3. An interactive preview exposes workload, runtime-event, and effective-policy
   views without requiring signup. It is explicitly labeled as sample data and
   remains separate from the operational dashboard.
4. Native disclosure elements keep FAQ navigation usable with keyboard and without
   client JavaScript. A mobile menu exposes all major landing sections.
5. The real dashboard keeps existing data fetching and mutation routes. Unavailable
   data is displayed as unavailable rather than a false zero fleet or empty feed.
6. Authentication uses the same brand and explains local enforcement alongside the
   existing provider widgets. Missing configuration gets a deliberate recovery state.

## Implementation plan and acceptance

1. Inspect routes, shared panels, auth integration, data access, and existing styles.
2. Research product positioning, operational hierarchy, architecture storytelling,
   accessibility, and technical claim boundaries using primary sources.
3. Rebuild the landing page and its navigation/preview; verify navigation and view
   changes without external writes.
4. Apply shared tokens and responsive layout to dashboard, host, settings, auth,
   and not-found views. Keep operational mode controls connected to existing API.
5. Run TypeScript and production build; check desktop and mobile layout, FAQ,
   preview controls, focus, and route rendering with browser automation.

Acceptance: all existing routes build, primary links lead to existing routes or
sections, preview data is labeled, operational data remains server sourced, mobile
navigation works, wide tables scroll locally, and no unsupported security guarantee
is introduced. Existing unrelated work in the repository is preserved.

## State coverage

| Surface | States covered |
| --- | --- |
| Landing | Signed-out/signed-in CTA; mobile menu closed/open; preview’s three views; FAQ closed/open; reduced motion |
| Overview | Control-plane response/unavailable; empty/populated fleet; events response/unavailable; real zero vs unavailable counts |
| Workload | Existing not-found behavior; unavailable connection; policy absent/present; blast radius; CVEs; event feed |
| Mode control | Existing selected, busy, refresh, and server-error behavior retained |
| Auth | Configured Clerk widgets; missing configuration; matching recovery layout |
| Layout | Narrow/mobile, tablet, desktop; keyboard focus; table scrolling |

## Limits

Competitor sites describe different architectures and cannot substantiate Vorynex
capabilities. Live account creation, external identity provider flows, and changes
to a real workload’s enforcement mode require configured services and are outside
visual verification. No deployment is part of this redesign.

## Verification evidence

- Headless Chromium with the system browser; screenshots inspected for landing,
  dashboard, populated workload, and auth recovery layouts.
- Landing checked at 320, 390, 768, and 1440 pixels: no page overflow; preview
  views, native FAQ disclosure, and mobile navigation passed.
- Overview, settings, workload, login, signup, and 404 checked at 390 and 1440
  pixels; WCAG A/AA automated axe scans returned zero violations after keyboard
  focus was added to the preview table and enrollment command scroll regions.
- A synthetic local control plane exercised populated and empty fleet states,
  workload navigation, selected protection mode, policy, blast radius, CVEs, and
  allowed/contained events. Populated workload scans passed at 390 and 1440 pixels.
- Enrollment navigation and keyboard skip link passed; no browser page errors.
- Browser checks deliberately used blank Clerk credentials in the test process,
  without modifying `.env.local`. The missing-configuration path exposed an
  unconditional Clerk provider; the provider and auth pages now consistently use
  `clerkConfigured` to render the intended setup recovery state.
- Existing enforcement mutations and authentication middleware are retained.
  Provider-backed sign-in and production workload mutations were not executed.
- Temporary browser tooling and screenshots live in `/tmp/vorynex-ui-qa`; no new
  production dependency was added.
- `cd web && npm run build && npm run typecheck` passed; `git diff --check`
  passed. The build uses the existing configured environment; browser fixtures
  use only process-scoped overrides.
