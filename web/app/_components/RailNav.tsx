"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const items = [
  { href: "/dashboard", label: "Overview" },
  { href: "/dashboard/settings", label: "Settings" },
];

export default function RailNav() {
  const pathname = usePathname();
  return (
    <nav className="rail-nav" aria-label="Dashboard">
      {items.map((item) => {
        const active = item.href === "/dashboard" ? pathname === "/dashboard" : pathname.startsWith(item.href);
        return (
          <Link key={item.href} className="rail-link" href={item.href} aria-current={active ? "page" : undefined}>
            <span>{item.label}</span>
          </Link>
        );
      })}
      <Link className="rail-link" href="/">
        <span>← Back to site</span>
      </Link>
    </nav>
  );
}
