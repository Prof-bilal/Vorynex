import Link from "next/link";
import { controlGet, type Host, type StoredEvent } from "@/lib/control";
import { EventList, HostsTable, isContained } from "../_components/panels";
import { NetworkIcon } from "../_components/icons";

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
          <h1>Runtime overview</h1>
          <p className="sub">
            Your workloads, their boundaries, and the operations that matter.
          </p>
        </div>
        <div className="topbar-actions">
          <Link
            className="btn btn-accent btn-sm"
            href="/dashboard/settings#enroll"
          >
            Enroll a workload <span aria-hidden="true">↗</span>
          </Link>
          <span className="status" data-state={online ? "ok" : "error"}>
            <span className="dot" aria-hidden="true" />
            <span>
              {online ? "Control plane connected" : "Control plane unreachable"}
            </span>
          </span>
        </div>
      </header>

      <div className="content">
        {!online && (
          <div className="connection-notice" role="status">
            <NetworkIcon />
            <div>
              <h3>Waiting for the control plane</h3>
              <p>
                Fleet data is unavailable. Existing local policies continue to
                enforce on enrolled hosts.{" "}
                <Link href="/dashboard/settings">
                  Review your connection settings →
                </Link>
              </p>
            </div>
          </div>
        )}

        <section className="stats" aria-label="Summary">
          <div className="stat">
            <span className="stat-k">Workloads</span>
            <span className="stat-v">{online ? hosts.length : "—"}</span>
            <span className="stat-note">
              {online ? "Enrolled in your workspace" : "Awaiting connection"}
            </span>
          </div>
          <div className="stat">
            <span className="stat-k">Events</span>
            <span className="stat-v">{eventsRes ? events.length : "—"}</span>
            <span className="stat-note">Recent telemetry · up to 300</span>
          </div>
          <div className="stat">
            <span className="stat-k">Contained</span>
            <span className="stat-v stat-v-ok">
              {eventsRes ? contained : "—"}
            </span>
            <span className="stat-note">
              Permission denials in recent events
            </span>
          </div>
          <div className="stat">
            <span className="stat-k">Mode</span>
            <span className="stat-v" style={{ fontSize: 18 }}>
              {hosts.length === 0
                ? "—"
                : new Set(hosts.map((h) => h.mode)).size === 1
                  ? hosts[0].mode
                  : "mixed"}
            </span>
            <span className="stat-note">Reported by enrolled hosts</span>
          </div>
        </section>

        <section className="panel-card" aria-labelledby="wl-title">
          <div className="panel-head">
            <h2 id="wl-title">Protected workloads</h2>
            <span className="hint">
              open a workload for policy, blast radius, and CVEs
            </span>
          </div>
          {online ? (
            <HostsTable hosts={hosts} events={events} />
          ) : (
            <div className="empty">
              <h3>Workload data unavailable</h3>
              <p>
                Connect the control plane to view enrolled workloads and their
                modes.
              </p>
            </div>
          )}
        </section>

        <section className="panel-card" aria-labelledby="ev-title">
          <div className="panel-head">
            <h2 id="ev-title">Recent events</h2>
            <Link className="hint" href="/dashboard/settings">
              agent setup →
            </Link>
          </div>
          {eventsRes ? (
            <EventList events={events} limit={10} />
          ) : (
            <div className="empty">
              <h3>Event data unavailable</h3>
              <p>
                The event feed will be available when the control plane
                reconnects.
              </p>
            </div>
          )}
        </section>
        {online && hosts.length === 0 && (
          <section className="dashboard-callout">
            <div>
              <h2>Your first boundary starts here.</h2>
              <p>
                Observe a workload, review its policy, and enroll it in your
                workspace.
              </p>
            </div>
            <Link className="btn btn-accent" href="/dashboard/settings#enroll">
              Set up an agent ↗
            </Link>
          </section>
        )}
      </div>
    </>
  );
}
