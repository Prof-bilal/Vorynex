import type { Metadata } from "next";
import { SignIn } from "@clerk/nextjs";
import NotConfigured from "../../_components/NotConfigured";
import AuthShell from "../../_components/AuthShell";
import { clerkConfigured } from "@/lib/auth";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Sign in" };

export default function LoginPage() {
  if (!clerkConfigured) return <NotConfigured mode="sign in" />;
  return (
    <AuthShell>
      <SignIn signUpUrl="/signup" fallbackRedirectUrl="/dashboard" />
    </AuthShell>
  );
}
