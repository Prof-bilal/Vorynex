"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

const MODES = ["observe", "protect", "lockdown"] as const;

export default function ModeControl({ hostId, mode }: { hostId: string; mode: string }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function setMode(next: string) {
    if (next === mode) return;
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/control/hosts/${encodeURIComponent(hostId)}/mode`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: next }),
      });
      if (!res.ok) {
        const j = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(j.error || `HTTP ${res.status}`);
      }
      startTransition(() => router.refresh());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not change mode");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="mode" role="group" aria-label="Protection mode">
        {MODES.map((m) => (
          <button
            key={m}
            type="button"
            aria-pressed={m === mode}
            disabled={busy || pending}
            onClick={() => setMode(m)}
            title={`Set ${hostId} to ${m}`}
          >
            {m}
          </button>
        ))}
      </div>
      {error && (
        <p className="muted" style={{ fontSize: 12, marginTop: 6, color: "var(--denied)" }}>
          {error}
        </p>
      )}
    </div>
  );
}
