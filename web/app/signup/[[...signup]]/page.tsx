import type { Metadata } from "next";
import { SignUp } from "@clerk/nextjs";
import NotConfigured from "../../_components/NotConfigured";
import AuthShell from "../../_components/AuthShell";
import { clerkConfigured } from "@/lib/auth";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Create your account" };

export default function SignupPage() {
  if (!clerkConfigured) return <NotConfigured mode="sign-up" />;
  return (
    <AuthShell>
      <SignUp signInUrl="/login" fallbackRedirectUrl="/dashboard" />
    </AuthShell>
  );
}
