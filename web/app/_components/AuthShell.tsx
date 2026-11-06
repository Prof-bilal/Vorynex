import Link from "next/link";
import ThemeToggle from "./ThemeToggle";
import { EyeIcon, ShieldIcon, NetworkIcon } from "./icons";

export default function AuthShell({ children }: { children: React.ReactNode }) {
  return (
    <main className="auth-layout">
      <div style={{ position: "fixed", top: 16, right: 16, zIndex: 5 }}>
        <ThemeToggle />
      </div>
      <aside className="auth-story">
        <Link className="brand" href="/">
          <span className="mark" aria-hidden="true" />
          vorynex<span className="brand-period">.</span>
        </Link>
        <div className="auth-story-copy">
          <p className="eyelabel">
            <span /> YOUR RUNTIME. YOUR BOUNDARY.
          </p>
          <h2>
            Give your app
            <br />
            <span>less room to risk.</span>
          </h2>
          <p>
            Understand what your application needs. Put a boundary around the
            rest.
          </p>
          <div className="auth-points">
            <span>
              <EyeIcon /> Learn from real application behavior
            </span>
            <span>
              <ShieldIcon /> Enforce least privilege on your host
            </span>
            <span>
              <NetworkIcon /> Keep visibility in one workspace
            </span>
          </div>
        </div>
        <span className="auth-story-foot">
          LOCAL ENFORCEMENT. CLOUD OPTIONAL.
        </span>
      </aside>
      <div className="auth-wrap">{children}</div>
    </main>
  );
}
