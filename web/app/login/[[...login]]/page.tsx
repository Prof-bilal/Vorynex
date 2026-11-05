import type { Metadata } from "next";
import { SignIn } from "@clerk/nextjs";
import NotConfigured from "../../_components/NotConfigured";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Sign in" };

const configured = Boolean(process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY);

export default function LoginPage() {
  if (!configured) return <NotConfigured mode="sign in" />;
  return (
    <div className="auth-wrap">
      <div className="aurora" aria-hidden="true" />
      <SignIn signUpUrl="/signup" fallbackRedirectUrl="/dashboard" />
    </div>
  );
}
