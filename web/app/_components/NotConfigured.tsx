import Link from "next/link";

export default function NotConfigured({ mode }: { mode: string }) {
  return (
    <div className="auth-wrap">
      <div className="aurora" aria-hidden="true" />
      <div className="auth-card">
        <Link className="brand" href="/">
          <span className="mark" aria-hidden="true" />
          Vorynex
        </Link>
        <h1>Auth is not configured</h1>
        <p className="sub">
          Add your Clerk keys to <span className="mono">web/.env.local</span> to enable {mode}.
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
    </div>
  );
}
