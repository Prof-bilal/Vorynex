import type { Metadata } from "next";
import Link from "next/link";
import { auth, currentUser } from "@clerk/nextjs/server";
import { UserButton } from "@clerk/nextjs";
import { clerkConfigured } from "@/lib/auth";
import Reveal from "./_components/Reveal";
import {
  EyeIcon,
  KeyIcon,
  KernelIcon,
  NetworkIcon,
  ShieldIcon,
  TerminalIcon,
} from "./_components/icons";

export const metadata: Metadata = {
  title: "Vorynex — Runtime containment for web apps",
};

const navLinks = [
  { href: "#why", label: "Why" },
  { href: "#how", label: "How it works" },
  { href: "#enforcement", label: "Enforcement" },
  { href: "#shield", label: "Emergency Shield" },
];

const faqs = [
  {
    q: "Is Vorynex a WAF?",
    a: "No. A WAF asks whether an HTTP request looks malicious. Vorynex assumes one will get through and limits what the workload can do afterwards. Keep the WAF; add a boundary behind it.",
  },
  {
    q: "Does it prevent every exploit?",
    a: "No, and we will never claim it. Vorynex reduces what an attacker can do after a vulnerability is exploited. It contains compromise; it does not remove the bug.",
  },
  {
    q: "What happens if the control plane is down?",
    a: "Nothing changes for your app. Enforcement is local, applied by the agent at the kernel boundary. A cloud outage must not disable protection, so the cloud is never in the request path.",
  },
  {
    q: "Will it break my app?",
    a: "Start in observe mode: zero enforcement, full visibility into what would have been blocked. Policies come from what your app actually did, and every proposed rule is validated against recorded traffic before it enforces.",
  },
  {
    q: "What does it run on today?",
    a: "Linux, on the host or inside Docker, for Node.js workloads. Spawn-time enforcement uses Landlock (unprivileged). Live enforcement uses four eBPF-LSM hooks and states honestly when a kernel cannot support them.",
  },
];

export default async function LandingPage() {
  // Rendered on the server so the signed-in name is in the first paint.
  const { userId } = clerkConfigured ? await auth() : { userId: null };
  const user = userId ? await currentUser() : null;
  const displayName =
    user?.firstName ||
    user?.username ||
    user?.primaryEmailAddress?.emailAddress?.split("@")[0] ||
    null;

  return (
    <>
      <header className="nav">
        <div className="wrap">
          <Link className="brand" href="/">
            <span className="mark" aria-hidden="true" />
            Vorynex
          </Link>
          <nav className="nav-links" aria-label="Sections">
            {navLinks.map((l) => (
              <a key={l.href} href={l.href}>
                {l.label}
              </a>
            ))}
          </nav>
          <span className="nav-spacer" />
          <div className="nav-actions">
            {displayName ? (
              <>
                <span className="nav-user">
                  Hi, <strong>{displayName}</strong>
                </span>
                <Link className="btn btn-ghost btn-sm" href="/dashboard">
                  Dashboard
                </Link>
                <UserButton />
              </>
            ) : (
              <>
                <Link className="link-quiet" href="/login">
                  Sign in
                </Link>
                <Link className="btn btn-ghost" href="/signup">
                  Sign up
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      <main id="top">
        <div className="aurora" aria-hidden="true" />

        <section className="hero">
          <div className="wrap">
            <p className="eyebrow">
              <span className="pulse" aria-hidden="true" />
              Runtime containment for web apps
            </p>
            <h1>
              The app can still have bugs.
              <br />
              Exploiting them is a dead end.
            </h1>
            <p className="lede">
              Vorynex learns what your Node app needs, then enforces a least-privilege runtime boundary around it.
            </p>
            <div className="deny-row" aria-label="What is denied by default">
              <span className="deny">no shell</span>
              <span className="deny">no secrets</span>
              <span className="deny">no cloud credentials</span>
              <span className="deny">no arbitrary egress</span>
            </div>
            <div className="hero-cta">
              <Link className="btn btn-lg" href={displayName ? "/dashboard" : "/signup"}>
                {displayName ? "Go to dashboard" : "Start free"}
              </Link>
              <a className="btn btn-ghost btn-lg" href="#enforcement">
                How containment works
              </a>
            </div>
          </div>

          <div className="wrap">
            <div className="showcase-outer">
              <div className="showcase" aria-label="Product preview">
                <div className="chrome">
                  <span className="dots" aria-hidden="true">
                    <i />
                    <i />
                    <i />
                  </span>
                  <span className="label">payments-api · protect</span>
                  <span className="status">
                    <span className="d" aria-hidden="true" />
                    contained
                  </span>
                </div>
                <div className="panes">
                  <div className="pane">
                    <div className="pane-h">
                      <span className="t">Attack trace</span>
                      <span className="r">10:41:02</span>
                    </div>
                    <ol className="chain">
                      <li className="hop">
                        <span className="n">01</span>
                        <span className="v">Internet</span>
                        <span className="tag">ingress</span>
                      </li>
                      <li className="arw">
                        <span>↓</span>
                      </li>
                      <li className="hop">
                        <span className="n">02</span>
                        <span className="v">POST /api/run</span>
                        <span className="tag">request</span>
                      </li>
                      <li className="arw">
                        <span>↓</span>
                      </li>
                      <li className="hop">
                        <span className="n">03</span>
                        <span className="v">
                          node <span className="dim">payments-api</span>
                        </span>
                        <span className="tag ok">running</span>
                      </li>
                      <li className="arw">
                        <span>↓</span>
                      </li>
                      <li className="hop blocked">
                        <span className="n">04</span>
                        <span className="v">exec(/bin/bash -c …)</span>
                        <span className="tag">DENIED</span>
                      </li>
                    </ol>
                    <div className="pane-foot">
                      <span>policy unexpected-child-process</span>
                      <span>no shell spawned</span>
                    </div>
                  </div>
                  <div className="pane">
                    <div className="pane-h">
                      <span className="t">Blast radius</span>
                      <span className="r">if compromised</span>
                    </div>
                    <div className="blast">
                      <div className="col reach">
                        <h4>Reachable</h4>
                        <ul>
                          <li>
                            <span className="ico" aria-hidden="true">
                              !
                            </span>
                            PostgreSQL
                          </li>
                          <li>
                            <span className="ico" aria-hidden="true">
                              !
                            </span>
                            /app/uploads
                          </li>
                          <li>
                            <span className="ico" aria-hidden="true">
                              !
                            </span>
                            api.stripe.com
                          </li>
                        </ul>
                      </div>
                      <div className="col hold">
                        <h4>Contained</h4>
                        <ul>
                          <li>
                            <span className="ico" aria-hidden="true">
                              ✓
                            </span>
                            host filesystem
                          </li>
                          <li>
                            <span className="ico" aria-hidden="true">
                              ✓
                            </span>
                            SSH &amp; cloud keys
                          </li>
                          <li>
                            <span className="ico" aria-hidden="true">
                              ✓
                            </span>
                            shell &amp; metadata
                          </li>
                        </ul>
                      </div>
                    </div>
                    <div className="pane-foot">
                      <span>derived from the policy</span>
                      <span>no invented score</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="strip">
            <div className="wrap">
              <div className="strip-row">
                <span className="lbl">Built for</span>
                <div className="strip-items">
                  <span>Linux</span>
                  <span>Docker</span>
                  <span>Node.js</span>
                  <span>Next.js</span>
                  <span>Landlock</span>
                  <span>eBPF-LSM</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="section reveal" id="why">
          <div className="wrap">
            <div className="section-head">
              <p className="kicker">The difference</p>
              <h2>Two different questions</h2>
              <p className="section-sub">
                Request filtering tries to stop the attempt. Vorynex assumes one will get through and limits the
                consequence.
              </p>
            </div>
            <div className="compare">
              <div className="against">
                <h3>A WAF asks</h3>
                <p>Is this HTTP request malicious?</p>
              </div>
              <div className="for">
                <h3>Vorynex asks</h3>
                <p>Even if the code runs, what should this workload be allowed to do?</p>
              </div>
            </div>
          </div>
        </section>

        <section className="section reveal" id="enforcement">
          <div className="wrap">
            <div className="section-head">
              <p className="kicker">What is enforced</p>
              <h2>Runtime least privilege, in rules you can read</h2>
              <p className="section-sub">
                Not a score, not a model. A versioned policy of allow and deny rules, enforced at the kernel boundary on
                the host.
              </p>
            </div>
            <div className="bento">
              <article className="cell wide">
                <span className="ico-line">
                  <KernelIcon size={20} />
                </span>
                <h3>Enforcement is local, and never in the request path</h3>
                <p>
                  The agent applies policy on your machine. The control plane is optional — if it is unreachable,
                  policies keep enforcing and telemetry drains when it returns.
                </p>
                <div className="plane mono">
                  <span>filesystem.read&nbsp;&nbsp;/app</span>
                  <br />
                  <span>network.allow&nbsp;&nbsp;&nbsp;&nbsp;api.stripe.com</span>
                  <br />
                  <span style={{ color: "var(--denied)" }}>process.exec.deny&nbsp;/bin/bash</span>
                </div>
              </article>
              <article className="cell">
                <span className="ico-line">
                  <ShieldIcon size={20} />
                </span>
                <h3>Two tiers, one policy</h3>
                <p>Landlock at spawn time; four eBPF-LSM hooks on a workload you cannot restart.</p>
                <span className="tagline">spawn-time + live</span>
              </article>
              <article className="cell">
                <span className="ico-line">
                  <TerminalIcon size={20} />
                </span>
                <h3>File-granular exec</h3>
                <p>Allow <span className="mono">node</span>, deny <span className="mono">/bin/bash</span> — matched by inode, not by name convention.</p>
              </article>
              <article className="cell">
                <span className="ico-line">
                  <NetworkIcon size={20} />
                </span>
                <h3>Egress allowlist</h3>
                <p>Every outbound connection has to be named, so arbitrary callback traffic simply does not leave.</p>
              </article>
              <article className="cell">
                <span className="ico-line">
                  <KeyIcon size={20} />
                </span>
                <h3>Secrets stay unreadable</h3>
                <p>Deny rules win over grants, and high-confidence secret filenames are masked inside allowed trees.</p>
              </article>
              <article className="cell">
                <span className="ico-line">
                  <EyeIcon size={20} />
                </span>
                <h3>Observe first, always</h3>
                <p>Start with zero enforcement and a report of what would have been blocked. Tighten only when you choose.</p>
              </article>
            </div>
          </div>
        </section>

        <section className="section reveal" id="how">
          <div className="wrap">
            <div className="section-head">
              <p className="kicker">How it works</p>
              <h2>Three commands from running app to boundary</h2>
              <p className="section-sub">
                Nothing blocks until you say so, and the policy is generated from what the app already does.
              </p>
            </div>
            <div className="steps">
              <article className="step-card">
                <span className="num">01</span>
                <h3>Observe the baseline</h3>
                <p>Run with zero enforcement. Every file, exec and connection the workload needed is recorded.</p>
                <code className="cmd">
                  <span className="prompt">$ </span>vorynex observe -- node server.js
                </code>
              </article>
              <article className="step-card">
                <span className="num">02</span>
                <h3>Generate a policy</h3>
                <p>Dangerous classes become explicit denies. The result is reviewable, versioned and signed.</p>
                <code className="cmd">
                  <span className="prompt">$ </span>vorynex policy generate --from events.jsonl
                </code>
              </article>
              <article className="step-card">
                <span className="num">03</span>
                <h3>Enforce locally</h3>
                <p>Launch under the boundary, or attach live to a workload you cannot restart.</p>
                <code className="cmd">
                  <span className="prompt">$ </span>vorynex protect --from events.jsonl -- node server.js
                </code>
              </article>
            </div>
          </div>
        </section>

        <section className="section reveal" aria-label="Capability facts">
          <div className="wrap">
            <div className="metrics">
              <div className="metric">
                <div className="v">2</div>
                <div className="k">Enforcement tiers</div>
                <div className="s">spawn-time + live</div>
              </div>
              <div className="metric">
                <div className="v">4</div>
                <div className="k">Live kernel hooks</div>
                <div className="s">capable · exec · file · connect</div>
              </div>
              <div className="metric">
                <div className="v">7/7</div>
                <div className="k">Lab attacks contained</div>
                <div className="s">enforced in CI on every push</div>
              </div>
              <div className="metric">
                <div className="v">0</div>
                <div className="k">Cloud calls in the request path</div>
                <div className="s">enforcement is local</div>
              </div>
            </div>
          </div>
        </section>

        <section className="section reveal">
          <div className="wrap">
            <div className="section-head">
              <p className="kicker">Enforcement tiers</p>
              <h2>Where you can restart. Where you cannot.</h2>
            </div>
            <div className="grid-2">
              <div className="tier">
                <h3>Spawn-time</h3>
                <p className="env">Landlock · unprivileged · works inside Docker</p>
                <ul>
                  <li>
                    <span className="b">✓</span>Read and write limited to granted paths
                  </li>
                  <li>
                    <span className="b">✓</span>Exec limited to the workload&apos;s own runtime
                  </li>
                  <li>
                    <span className="b">✓</span>Outbound TCP denied unless allowlisted
                  </li>
                  <li>
                    <span className="b">✓</span>Inherited by every child process
                  </li>
                </ul>
              </div>
              <div className="tier">
                <h3>Live</h3>
                <p className="env">eBPF-LSM · cgroup-scoped · disarmed by default</p>
                <ul>
                  <li>
                    <span className="b">✓</span>Enforce on a workload that is already running
                  </li>
                  <li>
                    <span className="b">✓</span>File-granular exec and path control
                  </li>
                  <li>
                    <span className="b">✓</span>No restart, and a running workload is never killed
                  </li>
                  <li>
                    <span className="b">✓</span>Degrades honestly when the kernel cannot support it
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        <section className="section reveal" id="shield">
          <div className="wrap">
            <div className="section-head">
              <p className="kicker">Emergency Shield</p>
              <h2>A CVE drops. Contain it before you patch.</h2>
              <p className="section-sub">
                Vorynex maps an exploited vulnerability to the workloads that run it, drafts containment, and proves it
                before it enforces.
              </p>
            </div>
            <div className="grid-2" style={{ alignItems: "start" }}>
              <div className="panel">
                <span className="role">The pipeline</span>
                <div className="flow" style={{ marginTop: 14 }}>
                  <span className="step hot">new CVE</span>
                  <span className="sep">→</span>
                  <span className="step">affected workloads</span>
                  <span className="sep">→</span>
                  <span className="step">candidate containment</span>
                  <span className="sep">→</span>
                  <span className="step">deterministic validation</span>
                  <span className="sep">→</span>
                  <span className="step safe">observe</span>
                  <span className="sep">→</span>
                  <span className="step safe">protect</span>
                </div>
                <p className="muted" style={{ margin: 0, fontSize: 14.5, lineHeight: 1.65 }}>
                  Sources include CISA KEV, NVD, GitHub Security Advisories, OSV and vendor advisories. AI may summarize
                  and draft a rule; it never pushes an untested block into production.
                </p>
              </div>
              <div>
                <div className="note" style={{ marginBottom: 14 }}>
                  <strong>Mitigation is not a patch.</strong> Emergency Shield buys time. It does not replace fixing the
                  vulnerability.
                </div>
                <div className="panel">
                  <span className="role">Example</span>
                  <ul>
                    <li>
                      <span className="b">✓</span>2 affected workloads identified from their SBOMs
                    </li>
                    <li>
                      <span className="b">✓</span>shell execution from the web worker denied
                    </li>
                    <li>
                      <span className="b">✓</span>cloud metadata access denied
                    </li>
                    <li>
                      <span className="b">✓</span>validated against recorded traffic
                    </li>
                    <li>
                      <span className="b warn">!</span>egress restriction needs review
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="section reveal" id="local">
          <div className="wrap">
            <div className="section-head">
              <p className="kicker">Local-first</p>
              <h2>The cloud is optional. Protection is not.</h2>
            </div>
            <div className="split">
              <div className="panel">
                <span className="role">Vorynex Cloud</span>
                <h3>Control plane</h3>
                <ul>
                  <li>
                    <span className="b">✓</span>Fleet dashboard, event history, audit trail
                  </li>
                  <li>
                    <span className="b">✓</span>CVE intelligence and Emergency Shield
                  </li>
                  <li>
                    <span className="b">✓</span>Policy review and staged rollout
                  </li>
                  <li>
                    <span className="b warn">!</span>Never sits in the request path
                  </li>
                </ul>
              </div>
              <div className="panel">
                <span className="role">Vorynex Agent</span>
                <h3>Enforcement</h3>
                <ul>
                  <li>
                    <span className="b">✓</span>Applies policy at the kernel boundary
                  </li>
                  <li>
                    <span className="b">✓</span>Keeps enforcing with no network
                  </li>
                  <li>
                    <span className="b">✓</span>Buffers telemetry offline, exports later
                  </li>
                  <li>
                    <span className="b">✓</span>Verifies the policy signature before loading it
                  </li>
                </ul>
              </div>
              <div className="center-note">
                cloud unreachable → <b>policies keep enforcing</b> → telemetry drains on reconnect
              </div>
            </div>
          </div>
        </section>

        <section className="section reveal" id="faq">
          <div className="wrap">
            <div className="section-head">
              <p className="kicker">Straight answers</p>
              <h2>What Vorynex is — and is not</h2>
            </div>
            <div className="faq">
              {faqs.map((f) => (
                <details key={f.q}>
                  <summary>{f.q}</summary>
                  <div className="a">{f.a}</div>
                </details>
              ))}
            </div>
          </div>
        </section>

        <section className="final" id="start">
          <div className="wrap">
            <h2>Contain compromise. Not just attempts.</h2>
            <p>
              Vorynex reduces what an attacker can do after a vulnerability is exploited. It is not a WAF, a scanner, or
              a guarantee. It is runtime least privilege, made operable.
            </p>
            <div className="hero-cta">
              <Link className="btn btn-lg" href={displayName ? "/dashboard" : "/signup"}>
                {displayName ? "Open the dashboard" : "Start free"}
              </Link>
              <Link className="btn btn-ghost btn-lg" href={displayName ? "/dashboard/settings" : "/login"}>
                {displayName ? "Account" : "Sign in"}
              </Link>
            </div>
          </div>
        </section>
      </main>

      <footer>
        <div className="wrap">
          <span>© 2026 Vorynex · Built on Warden (MIT)</span>
          <span className="links">
            <a href="#how">How it works</a>
            <a href="#shield">Emergency Shield</a>
            <a href="https://github.com/Prof-bilal/Vorynex">GitHub</a>
          </span>
        </div>
      </footer>

      <Reveal />
    </>
  );
}
