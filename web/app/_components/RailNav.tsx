"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { KernelIcon, KeyIcon, NetworkIcon } from "./icons";

const items = [
  { href: "/dashboard", label: "Overview" },
  { href: "/dashboard/settings", label: "Settings" },
];

export default function RailNav() {
  const pathname = usePathname();
  return (
    <nav className="rail-nav" aria-label="Dashboard">
      {items.map((item) => {
        const active =
          item.href === "/dashboard"
            ? pathname === "/dashboard"
            : pathname.startsWith(item.href);
        return (
          <Link
            key={item.href}
            className="rail-link"
            href={item.href}
            aria-current={active ? "page" : undefined}
          >
            {item.href === "/dashboard" ? <KernelIcon /> : <KeyIcon />}
            <span>{item.label}</span>
          </Link>
        );
      })}
      <Link className="rail-link" href="/">
        <NetworkIcon />
        <span>Back to website ↗</span>
      </Link>
    </nav>
  );
}
