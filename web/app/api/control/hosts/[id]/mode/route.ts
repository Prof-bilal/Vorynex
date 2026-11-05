import { NextResponse, type NextRequest } from "next/server";
import { auth } from "@clerk/nextjs/server";
import { controlPost } from "@/lib/control";
import { clerkConfigured } from "@/lib/auth";

const MODES = new Set(["observe", "protect", "lockdown"]);

// Proxy for changing a host's protection mode. The browser never holds the
// control-plane token: this route checks the Clerk session, then forwards.
export async function POST(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  if (clerkConfigured) {
    const { userId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: "unauthorized" }, { status: 401 });
    }
  }

  const { id } = await params;
  let body: { mode?: string };
  try {
    body = (await request.json()) as { mode?: string };
  } catch {
    return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
  }

  const mode = body.mode ?? "";
  if (!MODES.has(mode)) {
    return NextResponse.json({ error: "mode must be observe, protect, or lockdown" }, { status: 400 });
  }

  const result = await controlPost(`/v1/hosts/${encodeURIComponent(id)}/mode`, { mode });
  if (!result.ok) {
    return NextResponse.json({ error: result.error ?? "control plane error" }, { status: result.status || 502 });
  }
  return NextResponse.json({ ok: true, host_id: id, mode });
}
