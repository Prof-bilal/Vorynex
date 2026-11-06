import Link from "next/link";
import { notFound } from "next/navigation";
import {
  controlGet,
  type Host,
  type PolicyView,
  type SbomView,
  type StoredEvent,
} from "@/lib/control";
import ModeControl from "../../../_components/ModeControl";
import {
  BlastPanel,
  CvePanel,
  EventList,
  PolicyPanel,
  ago,
  isContained,
} from "../../../_components/panels";

export const dynamic = "force-dynamic";

export default async function HostPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const hostId = decodeURIComponent(id);

  const [hostsRes, eventsRes, policy, sbom] = await Promise.all([
    controlGet<{ hosts: Host[] }>("/v1/hosts"),
    controlGet<{ events: StoredEvent[] }>(
      `/v1/events?host_id=${encodeURIComponent(hostId)}&limit=200`,
    ),
    controlGet<PolicyView>(`/v1/hosts/${encodeURIComponent(hostId)}/policy`),
    controlGet<SbomView>(`/v1/hosts/${encodeURIComponent(hostId)}/sbom`),
  ]);

  const host = hostsRes?.hosts?.find((h) => h.host_id === hostId);
  if (hostsRes !== null && !host) notFound();

  const events = eventsRes?.events ?? [];
  const own = events.filter((e) => !e.record?.gap);
  const contained = own.filter(isContained).length;
  const last = own
    .map((e) => e.record?.event?.timestamp)
    .filter(Boolean)
    .sort()
    .pop();

  return (
    <>
      <header className="topbar">
        <div>
          <h1>{host?.hostname || hostId}</h1>
          <p className="sub">
            <span className="mono">{hostId}</span> · {own.length} events ·{" "}
            {contained} contained · last {last ? ago(String(last)) : "—"}
          </p>
        </div>
        <div className="topbar-actions">
          {host ? <ModeControl hostId={host.host_id} mode={host.mode} /> : null}
          <Link className="btn btn-ghost btn-sm" href="/dashboard">
            Back
          </Link>
        </div>
      </header>

      <div className="content">
        {!hostsRes && (
          <div className="connection-notice" role="status">
            <div>
              <h3>Workload connection unavailable</h3>
              <p>
                Reconnect the control plane to load this workload’s current
                policy, telemetry, and protection mode.
              </p>
            </div>
          </div>
        )}
        <section className="panel-card" aria-labelledby="pol-title">
          <div className="panel-head">
            <h2 id="pol-title">Effective policy</h2>
            <span className="hint">
              uploaded by the agent and validated by the control plane
            </span>
          </div>
          <PolicyPanel policy={policy} />
        </section>

        <div className="host-panels">
          <section className="panel-card" aria-labelledby="blast-title">
            <div className="panel-head">
              <h2 id="blast-title">Blast radius</h2>
              <span className="hint">if this workload were compromised</span>
            </div>
            <BlastPanel policy={policy} />
          </section>

          <section className="panel-card" aria-labelledby="cve-title">
            <div className="panel-head">
              <h2 id="cve-title">Known CVEs</h2>
              <span className="hint">
                from the workload&apos;s uploaded SBOM
              </span>
            </div>
            <CvePanel sbom={sbom} />
          </section>
        </div>

        <section className="panel-card" aria-labelledby="ev-title">
          <div className="panel-head">
            <h2 id="ev-title">Recent events</h2>
            <span className="hint">contained vs allowed</span>
          </div>
          <EventList events={events} limit={40} />
        </section>
      </div>
    </>
  );
}
