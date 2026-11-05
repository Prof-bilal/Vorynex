import Link from "next/link";
import { controlGet, type Host, type StoredEvent } from "@/lib/control";
import { EventList, HostsTable, isContained } from "../_components/panels";

export const dynamic = "force-dynamic";

export default async function OverviewPage() {
  const [hostsRes, eventsRes] = await Promise.all([
    controlGet<{ hosts: Host[] }>("/v1/hosts"),
    controlGet<{ events: StoredEvent[] }>("/v1/events?limit=300"),
  ]);

  const hosts = hostsRes?.hosts ?? [];
  const events = eventsRes?.events ?? [];
  const contained = events.filter(isContained).length;
  const online = hostsRes !== null;

  return (
    <>
      <header className="topbar">
        <div>
          <h1>Overview</h1>
          <p className="sub">
            {hosts.length} workload{hosts.length === 1 ? "" : "s"} · {events.length} events · Tier 0 spawn-time
            containment
          </p>
        </div>
        <div className="topbar-actions">
          <span className="status" data-state={online ? "ok" : "error"}>
            <span className="dot" aria-hidden="true" />
            <span>{online ? "Control plane connected" : "Control plane unreachable"}</span>
          </span>
        </div>
      </header>

      <div className="content">
        {!online && (
          <div className="panel-card">
            <div className="empty">
              <h3>The control plane is unreachable</h3>
              <p>
                Start <span className="mono">vorynex-cloud</span> and set{" "}
                <span className="mono">VORYNEX_CLOUD_URL</span> / <span className="mono">VORYNEX_CLOUD_TOKEN</span> in{" "}
                <span className="mono">web/.env.local</span>.
              </p>
            </div>
          </div>
        )}

        <section className="stats" aria-label="Summary">
          <div className="stat">
            <span className="stat-k">Workloads</span>
            <span className="stat-v">{hosts.length}</span>
          </div>
          <div className="stat">
            <span className="stat-k">Events</span>
            <span className="stat-v">{events.length}</span>
          </div>
          <div className="stat">
            <span className="stat-k">Contained</span>
            <span className="stat-v stat-v-ok">{contained}</span>
          </div>
          <div className="stat">
            <span className="stat-k">Mode</span>
            <span className="stat-v" style={{ fontSize: 18 }}>
              {hosts.length === 0 ? "—" : new Set(hosts.map((h) => h.mode)).size === 1 ? hosts[0].mode : "mixed"}
            </span>
          </div>
        </section>

        <section className="panel-card" aria-labelledby="wl-title">
          <div className="panel-head">
            <h2 id="wl-title">Protected workloads</h2>
            <span className="hint">open a workload for policy, blast radius, and CVEs</span>
          </div>
          <HostsTable hosts={hosts} events={events} />
        </section>

        <section className="panel-card" aria-labelledby="ev-title">
          <div className="panel-head">
            <h2 id="ev-title">Recent events</h2>
            <Link className="hint" href="/dashboard/settings">
              agent setup →
            </Link>
          </div>
          <EventList events={events} limit={10} />
        </section>
      </div>
    </>
  );
}
