import Link from "next/link";
import { currentUser } from "@clerk/nextjs/server";
import { controlGet, type Host } from "@/lib/control";
import { clerkConfigured, supabaseConfigured } from "@/lib/auth";
import RailNav from "../_components/RailNav";
import ThemeToggle from "../_components/ThemeToggle";
import SignOutButton from "../_components/SignOutButton";

export const dynamic = "force-dynamic";

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const user = clerkConfigured ? await currentUser() : null;
  const email =
    user?.primaryEmailAddress?.emailAddress ??
    user?.emailAddresses?.[0]?.emailAddress ??
    null;

  const hostsRes = await controlGet<{ hosts: Host[] }>("/v1/hosts");
  const online = hostsRes !== null;
  const hostCount = hostsRes?.hosts?.length ?? 0;

  return (
    <div className="app">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <aside className="rail">
        <Link className="brand" href="/dashboard">
          <span className="mark" aria-hidden="true" />
          vorynex<span className="brand-period">.</span>
        </Link>
        <div className="workspace-label">
          Runtime workspace <span>LOCAL</span>
        </div>
        <RailNav />
        <div className="rail-foot">
          <div className="rail-status">
            <div className="rail-row">
              <span className="rail-k">Control plane</span>
              <span className="rail-v" data-ok={online}>
                <i aria-hidden="true" />
                {online ? "connected" : "unreachable"}
              </span>
            </div>
            <div className="rail-row">
              <span className="rail-k">Hosts</span>
              <span className="rail-v">{hostCount}</span>
            </div>
            <div className="rail-row">
              <span className="rail-k">Database</span>
              <span className="rail-v">
                {supabaseConfigured() ? "Supabase" : "none"}
              </span>
            </div>
          </div>
          <div className="rail-user" title={email ?? undefined}>
            <span className="rail-k">{clerkConfigured ? "Signed in" : "Auth off"}</span>
            <span className="rail-v">{email ?? "local (no auth)"}</span>
          </div>
          <div className="rail-actions">
            {clerkConfigured && user ? <SignOutButton /> : null}
            <ThemeToggle />
          </div>
        </div>
      </aside>
      <main className="main" id="main-content">
        <div className="dashboard-breadcrumb">
          Workspace <span>/</span>
          <span>Runtime security</span>
        </div>
        {children}
      </main>
    </div>
  );
}
