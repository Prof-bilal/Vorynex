import Link from "next/link";
import AuthShell from "./AuthShell";

export default function NotConfigured({ mode }: { mode: string }) {
  return (
    <AuthShell>
      <div className="auth-card">
        <Link className="brand" href="/">
          <span className="mark" aria-hidden="true" />
          Vorynex
        </Link>
        <h1>Your workspace is almost ready.</h1>
        <p className="sub">
          Add your Clerk keys to <span className="mono">web/.env.local</span> to
          enable {mode}.
        </p>
        <p className="alert alert-note">
          <span className="mono">NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY</span>
          <br />
          <span className="mono">CLERK_SECRET_KEY</span>
        </p>
        <p className="auth-alt">
          <Link href="/">← Back to the site</Link>
        </p>
      </div>
    </AuthShell>
  );
}
