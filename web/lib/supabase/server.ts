import { createClient, type SupabaseClient } from "@supabase/supabase-js";

/**
 * Server-only Supabase client — Supabase is the DATABASE, auth is Clerk.
 *
 * Uses the service-role key, which bypasses RLS, so this must never be imported
 * from a client component. Route handlers and server components only.
 */
let cached: SupabaseClient | null = null;

export function db(): SupabaseClient | null {
  const url = process.env.SUPABASE_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return null;
  if (!cached) {
    cached = createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });
  }
  return cached;
}
