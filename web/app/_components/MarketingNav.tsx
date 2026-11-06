"use client";

import Link from "next/link";
import { useState } from "react";
import ThemeToggle from "./ThemeToggle";

export default function MarketingNav({ signedIn }: { signedIn: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <header className="landing-nav">
      <div className="wrap">
        <Link className="brand" href="/" aria-label="Vorynex home">
          <span className="mark" aria-hidden="true" />
          vorynex<span className="brand-period">.</span>
        </Link>
        <nav
          className="landing-links"
          aria-label="Main navigation"
          data-open={open}
        >
          <a href="#platform" onClick={() => setOpen(false)}>
            Platform
          </a>
          <a href="#how" onClick={() => setOpen(false)}>
            How it works
          </a>
          <a href="#enforcement" onClick={() => setOpen(false)}>
            Architecture
          </a>
          <a href="#faq" onClick={() => setOpen(false)}>
            FAQ
          </a>
        </nav>
        <div className="landing-nav-actions">
          <ThemeToggle />
          <Link className="nav-login" href={signedIn ? "/dashboard" : "/login"}>
            {signedIn ? "Dashboard" : "Log in"}
          </Link>
          <Link
            className="btn btn-accent btn-sm"
            href={signedIn ? "/dashboard" : "/signup"}
          >
            Get started <span aria-hidden="true">↗</span>
          </Link>
          <button
            className="menu-toggle"
            type="button"
            aria-label={open ? "Close navigation" : "Open navigation"}
            aria-expanded={open}
            onClick={() => setOpen(!open)}
          >
            {open ? "×" : "☰"}
          </button>
        </div>
      </div>
    </header>
  );
}
