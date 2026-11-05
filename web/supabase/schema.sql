-- Vorynex web — Supabase schema
--
-- Auth is **Clerk**; Supabase is the **database only**. Apply this once in the
-- Supabase SQL editor (or `supabase db push`).
--
-- Access model: only server-side code and the Go control plane touch these
-- tables, both with the service-role key. RLS is enabled with **no policies**,
-- so the anon/authenticated roles can read nothing even if a key leaks. User
-- identity comes from Clerk as a text id — there is no `auth.users` foreign key.

-- ---------- organizations + membership (tenant boundary) ----------
create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  clerk_org_id text,
  created_at timestamptz not null default now()
);

create table if not exists public.organization_members (
  org_id uuid references public.organizations(id) on delete cascade,
  user_id text not null,          -- Clerk user id (user_...)
  role text not null default 'member' check (role in ('owner', 'admin', 'member', 'viewer')),
  created_at timestamptz not null default now(),
  primary key (org_id, user_id)
);

-- ---------- hosts (durable fleet state for the M7 store) ----------
create table if not exists public.hosts (
  id text primary key,            -- the agent's host_id
  org_id uuid references public.organizations(id) on delete set null,
  hostname text,
  mode text not null default 'observe' check (mode in ('observe', 'protect', 'lockdown')),
  policy_yaml text,
  updated_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

-- ---------- events (mirror of ingested telemetry) ----------
create table if not exists public.events (
  id bigserial primary key,
  host_id text not null,
  seq bigint not null,
  ts timestamptz,
  type text,
  action text,
  resource text,
  allowed boolean,
  reason text,
  created_at timestamptz not null default now()
);

create index if not exists hosts_org_id_idx on public.hosts (org_id);
create index if not exists events_host_seq_idx on public.events (host_id, seq desc);
create index if not exists members_user_idx on public.organization_members (user_id);

-- ---------- lock it down ----------
alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;
alter table public.hosts enable row level security;
alter table public.events enable row level security;

-- Intentionally no policies. The service role bypasses RLS and is the only
-- credential the server or the control plane uses. When the Next.js app grows
-- direct reads, add policies that check organization membership against the
-- Clerk user id passed down by the server — never trust a browser-supplied id.

-- ---------- migration from the Supabase-auth version ----------
-- If you already ran an earlier schema that created `profiles` and FK columns
-- pointing at auth.users, drop the old objects (no data worth keeping yet):
--
--   drop trigger if exists on_auth_user_created on auth.users;
--   drop function if exists public.handle_new_user();
--   drop table if exists public.profiles;
--
-- The `hosts`/`events` tables here are compatible with the Go control plane
-- mirror (`SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY`).

-- ---------- verify (runs as part of the same script) ----------
select c.relname as table_name, c.relrowsecurity as row_security
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relname in ('organizations', 'organization_members', 'hosts', 'events')
order by c.relname;
