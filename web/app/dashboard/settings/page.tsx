import { currentUser } from "@clerk/nextjs/server";
import { clerkConfigured, supabaseConfigured } from "@/lib/auth";

export const dynamic = "force-dynamic";

export const metadata = { title: "Settings" };

export default async function SettingsPage() {
  const user = clerkConfigured ? await currentUser() : null;
  const email =
    user?.primaryEmailAddress?.emailAddress ?? user?.emailAddresses?.[0]?.emailAddress ?? null;
  const name = [user?.firstName, user?.lastName].filter(Boolean).join(" ") || null;

  const cloudUrl = process.env.VORYNEX_CLOUD_URL ?? "(not set)";
  const hasToken = Boolean(process.env.VORYNEX_CLOUD_TOKEN);
  const dbUrl = process.env.SUPABASE_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL;

  return (
    <>
      <header className="topbar">
        <div>
          <h1>Settings</h1>
          <p className="sub">Account, database, control plane, and agent enrollment</p>
        </div>
      </header>

      <div className="content">
        <section className="panel-card">
          <div className="panel-head">
            <h2>Account</h2>
            <span className="hint">Clerk</span>
          </div>
          <div style={{ padding: 18, display: "grid", gap: 6 }}>
            <div className="rail-meta" style={{ borderTop: 0, paddingTop: 0 }}>
              <span className="rail-k">Auth provider</span>
              <span className="rail-v">{clerkConfigured ? "Clerk" : "not configured"}</span>
            </div>
            <div className="rail-meta" style={{ borderTop: 0, paddingTop: 0 }}>
              <span className="rail-k">Signed in as</span>
              <span className="rail-v">{email ?? "local (auth disabled)"}</span>
            </div>
            {name ? (
              <div className="rail-meta" style={{ borderTop: 0, paddingTop: 0 }}>
                <span className="rail-k">Name</span>
                <span className="rail-v">{name}</span>
              </div>
            ) : null}
            <div className="rail-meta" style={{ borderTop: 0, paddingTop: 0 }}>
              <span className="rail-k">User id</span>
              <span className="rail-v">{user?.id ?? "—"}</span>
            </div>
          </div>
        </section>

        <section className="panel-card">
          <div className="panel-head">
            <h2>Database</h2>
            <span className="hint">Supabase (server-side only)</span>
          </div>
          <div style={{ padding: 18, display: "grid", gap: 6 }}>
            <div className="rail-meta" style={{ borderTop: 0, paddingTop: 0 }}>
              <span className="rail-k">Status</span>
              <span className="rail-v">
                {supabaseConfigured() ? `${dbUrl} · service role configured` : "not configured"}
              </span>
            </div>
            <p className="muted" style={{ margin: 0, fontSize: 13.5 }}>
              Apply <span className="mono">web/supabase/schema.sql</span> once in the Supabase SQL editor. The browser
              never touches this database; only server code and the Go control plane do.
            </p>
          </div>
        </section>

        <section className="panel-card">
          <div className="panel-head">
            <h2>Control plane</h2>
            <span className="hint">server-side only</span>
          </div>
          <div style={{ padding: 18, display: "grid", gap: 6 }}>
            <div className="rail-meta" style={{ borderTop: 0, paddingTop: 0 }}>
              <span className="rail-k">URL</span>
              <span className="rail-v">{cloudUrl}</span>
            </div>
            <div className="rail-meta" style={{ borderTop: 0, paddingTop: 0 }}>
              <span className="rail-k">Admin token</span>
              <span className="rail-v">{hasToken ? "set (server only)" : "not set"}</span>
            </div>
          </div>
        </section>

        <section className="panel-card">
          <div className="panel-head">
            <h2>Enroll an agent</h2>
            <span className="hint">run on the host you want to protect</span>
          </div>
          <div style={{ padding: 18, display: "grid", gap: 12 }}>
            <pre
              className="mono"
              style={{
                margin: 0,
                padding: 14,
                background: "var(--sunken)",
                border: "1px solid var(--line)",
                borderRadius: 10,
                fontSize: 12.5,
                overflowX: "auto",
              }}
            >{`# 1) record a baseline with zero enforcement
vorynex observe -- node server.js

# 2) generate a reviewable policy from what it actually needed
vorynex policy generate --from events.jsonl --out policy.yaml

# 3) enroll and upload telemetry + the effective policy
vorynex telemetry export \\
  --endpoint ${cloudUrl} \\
  --token <admin-token> \\
  --policy policy.yaml

# 4) correlate dependencies and upload the SBOM
vorynex cve scan --lockfile package-lock.json --live --nvd --upload \\
  --endpoint ${cloudUrl}`}</pre>
            <p className="muted" style={{ margin: 0, fontSize: 13.5 }}>
              Enrollment issues a per-host token that the agent stores and uses from then on. Rotate it from the
              control plane with <span className="mono">POST /v1/hosts/&lt;id&gt;/rotate-token</span>.
            </p>
          </div>
        </section>
      </div>
    </>
  );
}
