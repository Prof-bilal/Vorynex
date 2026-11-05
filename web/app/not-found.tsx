import Link from "next/link";

export default function NotFound() {
  return (
    <div className="auth-wrap">
      <div className="aurora" aria-hidden="true" />
      <div className="auth-card">
        <Link className="brand" href="/">
          <span className="mark" aria-hidden="true" />
          Vorynex
        </Link>
        <h1>Page not found</h1>
        <p className="sub">That page does not exist — or the link is out of date.</p>
        <p className="auth-alt">
          <Link href="/">← Back to the site</Link>
        </p>
      </div>
    </div>
  );
}
