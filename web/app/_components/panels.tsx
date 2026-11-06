import Link from "next/link";
import type {
  BlastRadius,
  Host,
  PolicyView,
  SbomView,
  StoredEvent,
} from "@/lib/control";

export function fmtTime(ts: string | undefined) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleTimeString([], { hour12: false });
}

export function ago(ts: string | undefined) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return "—";
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// "Contained" means the kernel refused the access. strace records every failed
// syscall as allowed:false, including harmless ENOENT misses, so count only
// permission denials.
export function isContained(e: StoredEvent) {
  const ev = e.record?.event;
  if (!ev || ev.allowed !== false) return false;
  const reason = String(ev.reason || "");
  return reason.includes("EACCES") || reason.includes("EPERM");
}

function statusBadge(events: number, contained: number) {
  if (events === 0) return <span className="badge badge-allowed">no data</span>;
  if (contained > 0)
    return <span className="badge badge-contained">reporting</span>;
  return <span className="badge badge-gap">stale</span>;
}

export function HostsTable({
  hosts,
  events,
}: {
  hosts: Host[];
  events: StoredEvent[];
}) {
  if (hosts.length === 0) {
    return (
      <div className="empty">
        <h3>No workloads enrolled yet</h3>
        <p>
          Run{" "}
          <span className="mono">
            vorynex telemetry export --endpoint &lt;control-plane&gt;
          </span>{" "}
          on a host to enroll it.
        </p>
      </div>
    );
  }
  return (
    <div
      className="table-scroll"
      role="region"
      aria-label="Workloads"
      tabIndex={0}
    >
      <table className="table">
        <thead>
          <tr>
            <th>Workload</th>
            <th>Mode</th>
            <th className="num">Events</th>
            <th className="num">Contained</th>
            <th>Last event</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((h) => {
            const own = events.filter(
              (e) => e.host_id === h.host_id && !e.record?.gap,
            );
            const contained = own.filter(isContained).length;
            const last = own
              .map((e) => e.record?.event?.timestamp)
              .filter(Boolean)
              .sort()
              .pop();
            return (
              <tr key={h.host_id}>
                <td>
                  <Link
                    className="row-btn"
                    href={`/dashboard/hosts/${encodeURIComponent(h.host_id)}`}
                  >
                    <span className="mono">{h.hostname || h.host_id}</span>
                    {h.hostname ? (
                      <span className="mono muted wl-id">{h.host_id}</span>
                    ) : null}
                  </Link>
                </td>
                <td>
                  <span
                    className={`badge ${h.mode === "protect" ? "badge-contained" : "badge-allowed"}`}
                  >
                    {h.mode}
                  </span>
                </td>
                <td className="num">{own.length}</td>
                <td className="num">{contained}</td>
                <td className="muted">{last ? ago(String(last)) : "—"}</td>
                <td>{statusBadge(own.length, contained)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function EventList({
  events,
  limit = 40,
}: {
  events: StoredEvent[];
  limit?: number;
}) {
  const rows = events.filter((e) => !e.record?.gap).slice(0, limit);
  if (rows.length === 0) {
    return (
      <div className="empty">
        <h3>No events yet</h3>
        <p>
          Telemetry appears here once an agent exports and a workload exercises
          its boundary.
        </p>
      </div>
    );
  }
  return (
    <ul className="timeline">
      {rows.map((e, i) => {
        const ev = e.record.event;
        const contained = isContained(e);
        // A failed syscall that was not a permission denial (an ENOENT miss) is
        // worth noticing but is not containment — give it its own tone.
        const tone = contained
          ? "badge-contained"
          : ev.allowed
            ? "badge-allowed"
            : "badge-gap";
        const label = contained ? "contained" : ev.allowed ? "allowed" : "miss";
        const time = fmtTime(ev.timestamp);
        const showTime =
          i === 0 || time !== fmtTime(rows[i - 1].record.event.timestamp);
        return (
          <li className="event" key={`${e.host_id}-${e.record.seq}`}>
            <span className="t">{showTime ? time : ""}</span>
            <span className="r">
              <span className="muted">{ev.action}</span> {ev.resource}
            </span>
            <span className={`b badge ${tone}`}>{label}</span>
          </li>
        );
      })}
    </ul>
  );
}

export function PolicyPanel({ policy }: { policy: PolicyView | null }) {
  if (!policy) {
    return (
      <div className="empty">
        <h3>No policy uploaded</h3>
        <p>The agent uploads its effective policy with:</p>
        <p className="mono muted">
          vorynex telemetry export --policy &lt;file&gt; --endpoint &lt;url&gt;
        </p>
      </div>
    );
  }
  const s = policy.summary;
  // The control plane marshals empty Go slices as null, so normalize here.
  const groups: [string, string[]][] = [
    ["Read (ro)", s.read ?? []],
    ["Write (rw)", s.write ?? []],
    ["Denied paths", s.deny ?? []],
    ["Exec allow", s.exec_allow ?? []],
    ["Exec deny", s.exec_deny ?? []],
    ["Network allow", s.network_allow ?? []],
  ];
  return (
    <>
      <div className="pol-head">
        <span className="badge">schema v{s.version}</span>
        <span
          className={`badge ${s.protect_secrets ? "badge-contained" : "badge-allowed"}`}
        >
          {s.protect_secrets ? "secret protection on" : "secret protection off"}
        </span>
      </div>
      <div className="pol-grid">
        {groups.map(([label, items]) => (
          <div className="pol-col" key={label}>
            <h4>{label}</h4>
            {items.length === 0 ? (
              <p className="muted" style={{ margin: 0, fontSize: 12.5 }}>
                —
              </p>
            ) : (
              <ul>
                {items.slice(0, 12).map((x) => (
                  <li key={x}>{x}</li>
                ))}
                {items.length > 12 ? (
                  <li className="muted">+{items.length - 12} more</li>
                ) : null}
              </ul>
            )}
          </div>
        ))}
      </div>
      <p className="muted pol-foot">
        Deny always wins over allow. The control plane validated this policy
        before it was stored.
      </p>
    </>
  );
}

export function BlastPanel({ policy }: { policy: PolicyView | null }) {
  if (!policy?.blast_radius) {
    return (
      <div className="empty">
        <h3>No policy-derived blast radius yet</h3>
        <p>
          Upload an effective policy to see exactly what this workload can
          reach.
        </p>
      </div>
    );
  }
  const r: BlastRadius = policy.blast_radius;
  const reachable = r.reachable ?? [];
  const contained = r.contained ?? [];
  return (
    <>
      <div className="blast-grid">
        <div className="col reach">
          <h4>Reachable</h4>
          {reachable.length === 0 ? (
            <p className="muted" style={{ margin: 0, fontSize: 13 }}>
              Nothing reachable within the policy
            </p>
          ) : (
            <ul>
              {reachable.slice(0, 12).map((x) => (
                <li key={`${x.kind}-${x.target}`}>
                  <span className="ico" aria-hidden="true">
                    !
                  </span>
                  <span>
                    {x.kind} {x.target}
                    {x.via ? <span className="muted"> · {x.via}</span> : null}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="col hold">
          <h4>Contained</h4>
          {contained.length === 0 ? (
            <p className="muted" style={{ margin: 0, fontSize: 13 }}>
              No danger classes contained
            </p>
          ) : (
            <ul>
              {contained.map((c) => (
                <li key={c.class}>
                  <span className="ico" aria-hidden="true">
                    ✓
                  </span>
                  <span>
                    {c.class}
                    {c.reason ? (
                      <span className="muted"> · {c.reason}</span>
                    ) : null}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
      <p className="blast-foot muted">
        Derived from the uploaded policy — every line is a rule, not a score.
      </p>
    </>
  );
}

export function CvePanel({ sbom }: { sbom: SbomView | null }) {
  const entries = sbom?.sbom?.entries ?? [];
  const packages = sbom?.sbom?.packages ?? 0;
  if (entries.length === 0) {
    return (
      <div className="empty">
        <h3>No CVEs reported</h3>
        <p>The agent uploads a correlated SBOM with:</p>
        <p className="mono muted">
          vorynex cve scan --lockfile package-lock.json --live --nvd --upload
          --endpoint &lt;url&gt;
        </p>
      </div>
    );
  }
  return (
    <>
      <div
        className="table-scroll"
        role="region"
        aria-label="Known vulnerabilities"
        tabIndex={0}
      >
        <table className="table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Advisory</th>
              <th>Package</th>
              <th>Installed</th>
              <th>Fixed</th>
              <th>Exploited</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => {
              const sev = e.cvss
                ? `${e.cvss.score.toFixed(1)} ${e.cvss.severity}`
                : "—";
              const sevClass =
                e.cvss &&
                (e.cvss.severity === "CRITICAL" || e.cvss.severity === "HIGH")
                  ? "badge-danger"
                  : "badge-allowed";
              return (
                <tr key={`${e.advisory_id}-${e.name}-${e.version}`}>
                  <td>
                    <span className={`badge ${sevClass}`}>{sev}</span>
                  </td>
                  <td className="mono">
                    {e.advisory_id}
                    {e.aliases?.length ? (
                      <span className="muted"> ({e.aliases.join(", ")})</span>
                    ) : null}
                  </td>
                  <td className="mono">{e.name}</td>
                  <td className="mono">{e.version}</td>
                  <td className="mono">{e.fixed || "unknown"}</td>
                  <td>
                    {e.known_exploited ? (
                      <span className="badge badge-danger">KEV</span>
                    ) : (
                      <span className="muted">no</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="muted pol-foot">
        {entries.length} affected package(s) across {packages} dependencies.
      </p>
    </>
  );
}
