# Vorynex web

The Next.js app: marketing site, auth, and the fleet dashboard. One app, one
deploy — `/` is the landing page and `/dashboard` is the product.

**Auth is [Clerk](https://clerk.com). Supabase is the database only.**

## What's here

- **`/`** — landing page (how-it-works, capability facts, FAQ).
- **`/login`, `/signup`** — Clerk's prebuilt components on catch-all routes
  (`app/login/[[...login]]`, `app/signup/[[...signup]]`), dark-themed to match.
- **`/dashboard`** — fleet overview: workloads, protection mode, containment
  timeline.
- **`/dashboard/hosts/[id]`** — effective policy, policy-derived blast radius,
  known CVEs, recent events, mode control.
- **`/dashboard/settings`** — account (Clerk), database, control plane, and
  agent enrollment.

The browser never holds the control-plane token. Server components read the Go
control plane (`vorynex-cloud`) directly, and mutations go through
`/api/control/*`, which checks the **Clerk** session first.

## Setup

```bash
cd web
cp .env.example .env.local     # fill in Clerk + Supabase + control plane
npm install --include=dev
npm run dev                    # http://localhost:3000
```

### 1. Clerk (auth)

1. Create an application at <https://dashboard.clerk.com>.
2. Copy **Publishable key** and **Secret key** into `.env.local`
   (`NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`, `CLERK_SECRET_KEY`).
3. **User & Authentication → Email, phone, username**: for local development,
   turn *Verify at sign-up* off — otherwise every test signup sends a real
   verification email (and providers rate-limit that).
4. **User & Authentication → Social connections**: enable GitHub and Google.
   Clerk hosts the OAuth callback, so the provider redirect URI is
   `https://clerk.<your-domain>/v1/oauth_callback`
   (or the development instance URL Clerk shows you).
5. Keep the path env vars from `.env.example` (`/login`, `/signup`,
   `/dashboard`) so Clerk's components and redirects line up with our routes.

Without Clerk keys the app still builds and renders; the auth pages show a
"not configured" notice and the dashboard is left unprotected for local use.

**Why Clerk over Supabase Auth here:** prebuilt UI, MFA, bot protection and
session management out of the box, and it removes Supabase's built-in-SMTP mail
rate limit from the signup path. Supabase stays as the database, so you still
get Postgres and one place for fleet state.

### 2. Supabase (database)

1. Create a project at <https://supabase.com>.
2. Copy the **Project URL** — `https://<ref>.supabase.co`, *not* the
   `/rest/v1/` endpoint — and the **service_role** key into `.env.local`
   (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`).
3. Run [`supabase/schema.sql`](./supabase/schema.sql) in the SQL editor. It
   creates `organizations`, `organization_members`, `hosts`, and `events`
   (the durable fleet tables for the M7 store). RLS is enabled with **no
   policies**, so only the service role (server + Go control plane) can reach
   them. User ids are Clerk ids (text) — there is no `auth.users` dependency.
4. The service-role key is server-only. Never prefix it with `NEXT_PUBLIC_`.

### 3. Control plane

```bash
# terminal 1 (repo root)
go run ./cmd/vorynex-cloud --addr 127.0.0.1:8787 --token "<admin-token>"
```

```dotenv
# web/.env.local
VORYNEX_CLOUD_URL=http://127.0.0.1:8787
VORYNEX_CLOUD_TOKEN=<admin-token>
```

To make the control plane persist fleet state in Supabase as well, start it with
`SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` in its environment; hosts and
events are mirrored best-effort.

## Scripts

```bash
npm run dev        # dev server
npm run build      # production build (what CI runs)
npm run typecheck  # tsc --noEmit
```

For end-to-end auth tests, Clerk ships `@clerk/testing` (test users or a testing
token) — that replaces the Supabase-specific verifier this app used to have.
