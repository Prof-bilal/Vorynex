import type { Metadata } from "next";
import Link from "next/link";
import { auth } from "@clerk/nextjs/server";
import { clerkConfigured } from "@/lib/auth";
import {
  EyeIcon,
  KernelIcon,
  KeyIcon,
  NetworkIcon,
  ShieldIcon,
  TerminalIcon,
  GitHubIcon,
} from "./_components/icons";
import ProductPreview from "./_components/ProductPreview";
import MarketingNav from "./_components/MarketingNav";

export const metadata: Metadata = {
  title: "Vorynex — Give your app a boundary",
};

const faqs = [
  [
    "Is this a replacement for my WAF?",
    "Keep your WAF. Vorynex adds a runtime boundary behind it: if a request exploits a vulnerability, the workload still has only the permissions in its policy. It reduces blast radius; it does not remove the vulnerability.",
  ],
  [
    "Does my traffic go through Vorynex?",
    "No. Enforcement happens locally on your Linux host. Vorynex is never in the HTTP request path, and the optional control plane is used for visibility and management.",
  ],
  [
    "How do I avoid breaking legitimate behavior?",
    "Begin in observe mode with no enforcement. Exercise real application paths, generate a policy from recorded behavior, and review the permissions before switching to protect. A baseline only reflects the behavior you exercised.",
  ],
  [
    "What happens when the cloud goes offline?",
    "Local enforcement continues with the effective policy. The optional control plane can become unavailable without removing the runtime boundary. Central visibility and management resume when it reconnects.",
  ],
  [
    "What can I run today?",
    "Linux hosts and Docker with Node.js workloads. Spawn-time containment uses Landlock; live enforcement uses eBPF-LSM on supported kernels. Available controls depend on the host and enforcement tier.",
  ],
];

export default async function LandingPage() {
  const { userId } = clerkConfigured ? await auth() : { userId: null };
  const destination = userId ? "/dashboard" : "/signup";
  return (
    <div className="marketing">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <MarketingNav signedIn={Boolean(userId)} />
      <main id="main-content">
        <section className="landing-hero wrap">
          <div className="hero-copy">
            <a className="release-link" href="#enforcement">
              <span className="live-dot" /> Built for the moment after an
              exploit <span aria-hidden="true">↗</span>
            </a>
            <h1>
              Your app.
              <br />
              Its own <span>boundary.</span>
            </h1>
            <p className="hero-description">
              A vulnerability shouldn’t become a foothold. Vorynex learns what
              your app needs and contains what it doesn’t.
            </p>
            <div className="hero-actions">
              <Link className="btn btn-accent btn-lg" href={destination}>
                {userId ? "Open your dashboard" : "Get started"}{" "}
                <span aria-hidden="true">↗</span>
              </Link>
              <a className="btn btn-ghost btn-lg" href="#platform">
                Explore the platform <span aria-hidden="true">↓</span>
              </a>
            </div>
            <div className="hero-assurances">
              <span>
                <span aria-hidden="true">✓</span> Local enforcement
              </span>
              <span>
                <span aria-hidden="true">✓</span> Cloud optional
              </span>
              <span>
                <span aria-hidden="true">✓</span> Outside the request path
              </span>
            </div>
          </div>
          <div
            className="boundary-visual"
            role="img"
            aria-label="Illustrative runtime boundary: your Node.js app can access its app files and database, while shell execution and secret access are denied by policy."
          >
            <div className="visual-topline">
              <span>RUNTIME BOUNDARY</span>
              <span className="visual-state">
                <span className="live-dot" /> POLICY ACTIVE
              </span>
            </div>
            <div className="boundary-grid" aria-hidden="true">
              <div className="orbit orbit-one" />
              <div className="orbit orbit-two" />
              <div className="orbit orbit-three" />
              <div className="boundary-cross cross-one" />
              <div className="boundary-cross cross-two" />
              <div className="app-core">
                <span className="core-icon">
                  <KernelIcon size={34} />
                </span>
                <strong>your-app</strong>
                <span>node server.js</span>
                <small>
                  <span className="live-dot" /> CONTAINED RUNTIME
                </small>
              </div>
              <div className="resource resource-files">
                <span className="resource-icon">▤</span>
                <span>
                  App files<small>/app/**</small>
                </span>
                <b>✓</b>
              </div>
              <div className="resource resource-db">
                <NetworkIcon size={19} />
                <span>
                  Database<small>approved connection</small>
                </span>
                <b>✓</b>
              </div>
              <div className="resource resource-shell denied">
                <TerminalIcon size={19} />
                <span>
                  Spawn a shell<small>/bin/sh</small>
                </span>
                <b>×</b>
              </div>
              <div className="resource resource-secrets denied">
                <KeyIcon size={19} />
                <span>
                  Read secrets<small>/root/.ssh/**</small>
                </span>
                <b>×</b>
              </div>
              <svg
                className="boundary-lines"
                viewBox="0 0 540 380"
                preserveAspectRatio="none"
              >
                <path
                  d="M270 170 L130 86 M270 170 L410 96"
                  className="allowed-line"
                />
                <path
                  d="M270 200 L125 302 M270 200 L410 300"
                  className="denied-line"
                />
              </svg>
            </div>
            <div className="visual-bottomline">
              <span>LEAST PRIVILEGE. ENFORCED LOCALLY.</span>
              <span>ILLUSTRATIVE POLICY</span>
            </div>
          </div>
        </section>
        <div className="compatibility wrap">
          <span>BUILT FOR YOUR STACK</span>
          <div>
            <b>
              <span aria-hidden="true">◉</span> Linux
            </b>
            <b>
              <span aria-hidden="true">⬡</span> Node.js
            </b>
            <b>
              <span aria-hidden="true">▥</span> Docker
            </b>
            <b>
              <span aria-hidden="true">⌘</span> Landlock
            </b>
            <b>
              <span aria-hidden="true">⊞</span> eBPF
            </b>
          </div>
          <span>YOUR HOST. YOUR CONTROL.</span>
        </div>
        <section className="landing-section wrap" id="platform">
          <div className="section-heading">
            <div>
              <p className="eyelabel">
                <span /> THE PLATFORM
              </p>
              <h2>
                Know what’s running.
                <br />
                <span>Control what it can do.</span>
              </h2>
            </div>
            <p>
              From the fleet to a single denied operation.
              <br />A clear view of your runtime boundary.
            </p>
          </div>
          <ProductPreview />
          <div className="feature-row">
            {[
              {
                icon: <EyeIcon />,
                title: "Visibility with context",
                text: "See workload modes, effective policies, and runtime events in one place.",
              },
              {
                icon: <ShieldIcon />,
                title: "A smaller blast radius",
                text: "Understand which resources remain reachable if a workload is compromised.",
              },
              {
                icon: <TerminalIcon />,
                title: "Evidence you can inspect",
                text: "Trace containment to a concrete operation and the permission that denied it.",
              },
            ].map((f) => (
              <article key={f.title}>
                <span className="feature-icon">{f.icon}</span>
                <h3>{f.title}</h3>
                <p>{f.text}</p>
              </article>
            ))}
          </div>
        </section>
        <section className="how-section" id="how">
          <div className="wrap">
            <div className="section-heading">
              <div>
                <p className="eyelabel">
                  <span /> FROM OBSERVATION TO ENFORCEMENT
                </p>
                <h2>
                  Learn first.
                  <br />
                  <span>Enforce with confidence.</span>
                </h2>
              </div>
              <p>
                Start with your application’s real behavior.
                <br />
                Turn it into a boundary you can review.
              </p>
            </div>
            <div className="workflow-grid">
              {[
                {
                  n: "01",
                  icon: <EyeIcon />,
                  title: "Observe your app",
                  text: "Run real workflows. Record the files, processes, and connections your app uses, with no enforcement.",
                  command: "vorynex observe -- node server.js",
                },
                {
                  n: "02",
                  icon: <TerminalIcon />,
                  title: "Review the policy",
                  text: "Generate a least-privilege policy from the baseline. Inspect the rules and account for paths you haven’t exercised.",
                  command: "vorynex policy generate --from events.jsonl",
                },
                {
                  n: "03",
                  icon: <ShieldIcon />,
                  title: "Contain the unexpected",
                  text: "Enable local enforcement. Keep the permissions your app needs and constrain operations beyond its boundary.",
                  command:
                    "vorynex protect --from events.jsonl -- node server.js",
                },
              ].map((step) => (
                <article key={step.n}>
                  <div className="workflow-top">
                    <span>{step.n} /</span>
                    {step.icon}
                  </div>
                  <h3>{step.title}</h3>
                  <p>{step.text}</p>
                  <code>{step.command}</code>
                </article>
              ))}
            </div>
          </div>
        </section>
        <section className="landing-section wrap" id="enforcement">
          <div className="architecture-layout">
            <div>
              <p className="eyelabel">
                <span /> SECURITY THAT STAYS WITH YOUR APP
              </p>
              <h2>
                The boundary is local.
                <br />
                <span>The cloud is optional.</span>
              </h2>
              <p className="architecture-description">
                Your host enforces the policy. The control plane helps you see
                and manage it. Losing a cloud connection doesn’t remove your
                runtime boundary.
              </p>
              <a
                className="text-link"
                href="https://github.com/Prof-bilal/Vorynex"
              >
                Explore the architecture <span aria-hidden="true">↗</span>
              </a>
            </div>
            <div className="architecture-card">
              <div className="architecture-cloud">
                <NetworkIcon />
                <div>
                  <strong>Control plane</strong>
                  <span>Fleet visibility & management</span>
                </div>
                <small>OPTIONAL</small>
              </div>
              <div className="telemetry-link">
                <span>↑ telemetry</span>
                <span>↓ management</span>
              </div>
              <div className="architecture-host">
                <div className="host-label">
                  <span className="live-dot" /> YOUR LINUX HOST
                </div>
                <div className="host-parts">
                  <span>
                    <KernelIcon /> Your application
                  </span>
                  <span>
                    <ShieldIcon /> Local enforcement
                  </span>
                </div>
                <p>Landlock · eBPF-LSM on supported kernels</p>
              </div>
              <div className="architecture-note">
                <span aria-hidden="true">↳</span> HTTP requests go directly to
                your app.
              </div>
            </div>
          </div>
          <div className="capability-strip">
            <div>
              <strong>Spawn-time containment</strong>
              <span>Landlock · unprivileged boundary</span>
            </div>
            <div>
              <strong>Live enforcement</strong>
              <span>eBPF-LSM · supported kernels</span>
            </div>
            <div>
              <strong>Honest by design</strong>
              <span>Capabilities depend on the host and tier</span>
            </div>
          </div>
        </section>
        <section className="landing-section wrap" id="shield">
          <div className="shield-section">
            <div>
              <p className="eyelabel">
                <span /> EMERGENCY SHIELD
              </p>
              <h2>
                A new CVE.
                <br />
                <span>A reviewed response.</span>
              </h2>
              <p className="architecture-description">
                Match affected dependencies, draft a containment policy, and
                simulate it against recorded behavior before you decide to
                enforce.
              </p>
              <a
                className="text-link"
                href="https://github.com/Prof-bilal/Vorynex"
              >
                Inspect the containment workflow ↗
              </a>
            </div>
            <div className="shield-pipeline">
              <div>
                <span>01</span>
                <strong>Correlate dependencies</strong>
                <small>Identify affected packages</small>
              </div>
              <div>
                <span>02</span>
                <strong>Validate the candidate</strong>
                <small>Check rules and simulate recorded events</small>
              </div>
              <div>
                <span>03</span>
                <strong>Review, then observe</strong>
                <small>Confirm behavior before protecting</small>
              </div>
              <p>
                <ShieldIcon size={15} /> Mitigation buys time. Upgrade the
                affected package.
              </p>
            </div>
          </div>
        </section>
        <section className="landing-section wrap faq-layout" id="faq">
          <div>
            <p className="eyelabel">
              <span /> GOOD QUESTIONS
            </p>
            <h2>
              Clarity is part
              <br />
              <span>of the protection.</span>
            </h2>
            <p className="architecture-description">
              What Vorynex does, where it runs,
              <br />
              and what to expect.
            </p>
          </div>
          <div className="new-faq">
            {faqs.map(([q, a]) => (
              <details key={q}>
                <summary>
                  {q}
                  <span aria-hidden="true">+</span>
                </summary>
                <p>{a}</p>
              </details>
            ))}
          </div>
        </section>
        <section className="closing-section wrap">
          <div className="closing-mark">
            <ShieldIcon size={30} />
          </div>
          <p className="eyelabel">LESS PRIVILEGE. LESS ROOM TO MOVE.</p>
          <h2>
            Ship your app.
            <br />
            <span>Keep its world small.</span>
          </h2>
          <p>Build a runtime boundary around what your app actually needs.</p>
          <Link className="btn btn-accent btn-lg" href={destination}>
            {userId ? "Open dashboard" : "Get started with Vorynex"}{" "}
            <span aria-hidden="true">↗</span>
          </Link>
          <a
            className="closing-source"
            href="https://github.com/Prof-bilal/Vorynex"
          >
            <GitHubIcon /> Explore on GitHub
          </a>
        </section>
      </main>
      <footer className="landing-footer">
        <div className="wrap">
          <Link className="brand" href="/">
            <span className="mark" aria-hidden="true" />
            vorynex<span className="brand-period">.</span>
          </Link>
          <p>Runtime least privilege. Reduced blast radius.</p>
          <div>
            <a href="#platform">Platform</a>
            <a href="#how">How it works</a>
            <a href="https://github.com/Prof-bilal/Vorynex">GitHub ↗</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
