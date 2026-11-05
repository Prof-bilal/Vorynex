// Server-only access to the Go control plane (vorynex-cloud). The browser never
// holds the admin token; page code runs on the server and the mutation route
// handler proxies on the user's behalf after an auth check.

const BASE = (process.env.VORYNEX_CLOUD_URL ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const TOKEN = process.env.VORYNEX_CLOUD_TOKEN ?? "";

export type Host = {
  host_id: string;
  hostname: string;
  mode: "observe" | "protect" | "lockdown" | string;
  registered_at: string;
};

export type AuditEvent = {
  timestamp: string;
  type: string;
  action: string;
  resource: string;
  allowed: boolean;
  reason?: string;
  pid?: number;
};

export type StoredEvent = { host_id: string; record: { seq: number; event: AuditEvent; gap?: boolean } };

export type PolicySummary = {
  version: number;
  read: string[];
  write: string[];
  deny: string[];
  exec_allow: string[];
  exec_deny: string[];
  network_allow: string[];
  protect_secrets: boolean;
};

export type BlastRadius = {
  workload: string;
  mode: string;
  reachable: { kind: string; target: string; via: string; confidence: string }[];
  contained: { class: string; reason: string }[];
  warnings?: string[];
};

export type PolicyView = { host_id: string; yaml: string; summary: PolicySummary; blast_radius: BlastRadius };

export type SbomEntry = {
  name: string;
  version: string;
  advisory_id: string;
  aliases?: string[];
  summary?: string;
  fixed?: string;
  known_exploited?: boolean;
  cvss?: { score: number; severity: string; version?: string };
};

export type SbomView = {
  host_id: string;
  sbom: { workload: string; scanned_at: string; packages: number; entries: SbomEntry[] };
};

async function controlFetch(path: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (TOKEN) headers.set("Authorization", `Bearer ${TOKEN}`);
  if (init?.body) headers.set("Content-Type", "application/json");
  return fetch(`${BASE}${path}`, { ...init, headers, cache: "no-store" });
}

export async function controlGet<T>(path: string): Promise<T | null> {
  try {
    const res = await controlFetch(path);
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export async function controlPost(path: string, body: unknown): Promise<{ ok: boolean; status: number; error?: string }> {
  try {
    const res = await controlFetch(path, { method: "POST", body: JSON.stringify(body) });
    if (res.ok) return { ok: true, status: res.status };
    let error = `HTTP ${res.status}`;
    try {
      const j = (await res.json()) as { error?: string };
      if (j.error) error = j.error;
    } catch {
      /* keep the status text */
    }
    return { ok: false, status: res.status, error };
  } catch (err) {
    return { ok: false, status: 0, error: err instanceof Error ? err.message : "control plane unreachable" };
  }
}

export function controlPlaneConfigured(): boolean {
  return Boolean(process.env.VORYNEX_CLOUD_URL);
}
