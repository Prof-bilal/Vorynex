import type { Metadata } from "next";
import { SignUp } from "@clerk/nextjs";
import NotConfigured from "../../_components/NotConfigured";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Create your account" };

const configured = Boolean(process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY);

export default function SignupPage() {
  if (!configured) return <NotConfigured mode="sign-up" />;
  return (
    <div className="auth-wrap">
      <div className="aurora" aria-hidden="true" />
      <SignUp signInUrl="/login" fallbackRedirectUrl="/dashboard" />
    </div>
  );
}
