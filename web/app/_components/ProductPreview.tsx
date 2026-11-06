"use client";

import { useState } from "react";
import { EyeIcon, ShieldIcon, TerminalIcon, KernelIcon } from "./icons";

const views = ["Workloads", "Runtime events", "Effective policy"] as const;
const events = [
  ["14:32:08", "exec", "/bin/sh", "Denied"],
  ["14:32:08", "read", "/root/.ssh/id_rsa", "Denied"],
  ["14:31:56", "read", "/app/config.json", "Allowed"],
  ["14:31:42", "write", "/app/uploads/avatar.png", "Allowed"],
];

export default function ProductPreview() {
  const [view, setView] = useState<(typeof views)[number]>("Workloads");
  return (
    <div className="product-preview">
      <div className="preview-chrome">
        <div>
          <span className="window-dot" />
          <span className="window-dot" />
          <span className="window-dot" />
        </div>
        <span>Vorynex / Runtime overview</span>
        <span className="demo-label">INTERACTIVE DEMO · SAMPLE DATA</span>
      </div>
      <div className="preview-body">
        <aside className="preview-sidebar">
          <div className="brand">
            <span className="mark" />
            vorynex.
          </div>
          <span className="preview-workspace">
            ◈ &nbsp; Production <span>⌄</span>
          </span>
          <span className="preview-section-label">WORKSPACE</span>
          <div role="group" aria-label="Product preview views">
            {views.map((item, i) => (
              <button
                type="button"
                key={item}
                aria-pressed={view === item}
                onClick={() => setView(item)}
              >
                {i === 0 ? (
                  <KernelIcon size={16} />
                ) : i === 1 ? (
                  <EyeIcon size={16} />
                ) : (
                  <ShieldIcon size={16} />
                )}
                {item}
                {i === 0 && <small>3</small>}
              </button>
            ))}
          </div>
          <div className="preview-local">
            <span className="live-dot" /> Local enforcement active
            <small>Policy stays on your host</small>
          </div>
        </aside>
        <div className="preview-main">
          <div className="preview-title">
            <div>
              <span>
                Workspace <span aria-hidden="true">/</span> Production
              </span>
              <h3>{view === "Workloads" ? "Runtime overview" : view}</h3>
            </div>
            <span className="preview-environment">
              <span className="live-dot" /> Production
            </span>
          </div>
          <div className="preview-stats">
            <div>
              <span>Workloads</span>
              <strong>
                03<small>enrolled</small>
              </strong>
            </div>
            <div>
              <span>Enforcing workloads</span>
              <strong>
                02<small>of 3 workloads</small>
              </strong>
            </div>
            <div>
              <span>Contained operations</span>
              <strong className="accent-text">
                02<small>in this example</small>
              </strong>
            </div>
          </div>
          <div className="preview-data" aria-live="polite">
            {view === "Workloads" ? (
              <>
                <div className="preview-panel-title">
                  <strong>Workloads</strong>
                  <span>3 total</span>
                </div>
                <div
                  className="preview-table-scroll"
                  role="region"
                  aria-label="Example workloads"
                  tabIndex={0}
                >
                  <table className="preview-table">
                    <thead>
                      <tr>
                        <th>Workload</th>
                        <th>Mode</th>
                        <th>Boundary</th>
                        <th>Last event</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[
                        ["payments-api", "protect", "Enforcing", "just now"],
                        ["storefront", "protect", "Enforcing", "12s ago"],
                        ["background-worker", "observe", "Learning", "38s ago"],
                      ].map(([name, mode, boundary, time]) => (
                        <tr key={name}>
                          <td>
                            <span className="workload-glyph">
                              <TerminalIcon size={15} />
                            </span>
                            <strong>{name}</strong>
                            <small>Node.js · Linux</small>
                          </td>
                          <td>
                            <span
                              className={`preview-badge ${mode === "protect" ? "green" : "amber"}`}
                            >
                              {mode}
                            </span>
                          </td>
                          <td>
                            <span
                              className={
                                mode === "protect" ? "accent-text" : "muted"
                              }
                            >
                              ●
                            </span>{" "}
                            {boundary}
                          </td>
                          <td>{time}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : view === "Runtime events" ? (
              <>
                <div className="preview-panel-title">
                  <strong>Operation timeline</strong>
                  <span>payments-api</span>
                </div>
                {events.map(([time, action, resource, result]) => (
                  <div className="preview-event" key={resource}>
                    <time>{time}</time>
                    <code>
                      {action} <span>{resource}</span>
                    </code>
                    <span
                      className={`preview-badge ${result === "Denied" ? "red" : "green"}`}
                    >
                      {result}
                    </span>
                  </div>
                ))}
              </>
            ) : (
              <>
                <div className="preview-panel-title">
                  <strong>Effective policy</strong>
                  <span>payments-api · example excerpt</span>
                </div>
                <pre className="preview-policy">{`filesystem:\n  read: ["/app/**"]\n  write: ["/app/uploads/**"]\n  deny: ["/root/.ssh/**"]\n  protect_secrets: true\nprocess: {exec: {deny: ["/bin/sh"]}}`}</pre>
              </>
            )}
          </div>
          <div className="preview-bottom">
            <span>
              <ShieldIcon size={14} /> Enforcement is local. Visibility is
              centralized.
            </span>
            <span>↳ Explore the views</span>
          </div>
        </div>
      </div>
    </div>
  );
}
