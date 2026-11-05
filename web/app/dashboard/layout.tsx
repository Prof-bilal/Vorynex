import Link from "next/link";
import { currentUser } from "@clerk/nextjs/server";
import { controlGet, type Host } from "@/lib/control";
import { clerkConfigured, supabaseConfigured } from "@/lib/auth";
import RailNav from "../_components/RailNav";
import SignOutButton from "../_components/SignOutButton";

export const dynamic = "force-dynamic";

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const user = clerkConfigured ? await currentUser() : null;
  const email =
    user?.primaryEmailAddress?.emailAddress ?? user?.emailAddresses?.[0]?.emailAddress ?? null;

  const hostsRes = await controlGet<{ hosts: Host[] }>("/v1/hosts");
  const online = hostsRes !== null;
  const hostCount = hostsRes?.hosts?.length ?? 0;

  return (
    <div className="app">
      <aside className="rail">
        <Link className="brand" href="/dashboard">
          <span className="mark" aria-hidden="true" />
          Vorynex
        </Link>
        <RailNav />
        <div className="rail-foot">
          <div className="rail-meta">
            <span className="rail-k">Control plane</span>
            <span className="rail-v">{online ? "connected" : "unreachable"}</span>
            <span className="rail-v">
              {hostCount} host{hostCount === 1 ? "" : "s"}
            </span>
          </div>
          <div className="rail-meta">
            <span className="rail-k">{clerkConfigured ? "Signed in" : "Auth off"}</span>
            <span className="rail-v">{email ?? "local (no auth)"}</span>
            <span className="rail-v">{supabaseConfigured() ? "Supabase DB" : "no database"}</span>
          </div>
          {clerkConfigured && user ? <SignOutButton /> : null}
        </div>
      </aside>
      <div className="main">{children}</div>
    </div>
  );
}
