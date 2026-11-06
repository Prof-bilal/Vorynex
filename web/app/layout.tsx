import type { Metadata, Viewport } from "next";
import { ClerkProvider } from "@clerk/nextjs";
import { clerkConfigured } from "@/lib/auth";
import { Inter, Instrument_Serif, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const serif = Instrument_Serif({ subsets: ["latin"], weight: "400", style: ["normal", "italic"], variable: "--font-serif" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono" });

export const metadata: Metadata = {
  title: {
    default: "Vorynex — Runtime containment for web apps",
    template: "%s · Vorynex",
  },
  description:
    "Vorynex learns what your web app needs, enforces a local least-privilege runtime boundary, and reduces the blast radius of compromise. Cloud optional. Outside the request path.",
};

export const viewport: Viewport = {
  colorScheme: "light dark",
  themeColor: [{ media: "(prefers-color-scheme: light)", color: "#f5f2ea" }, { media: "(prefers-color-scheme: dark)", color: "#0f1012" }],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const page = (
    <html lang="en" suppressHydrationWarning className={`${inter.variable} ${serif.variable} ${mono.variable}`}>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `try{var t=localStorage.theme||(matchMedia("(prefers-color-scheme:dark)").matches?"dark":"light");document.documentElement.dataset.theme=t}catch(e){}`,
          }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
  if (!clerkConfigured) return page;
  return (
    <ClerkProvider
      appearance={{
        variables: {
          colorPrimary: "var(--accent)",
          colorPrimaryForeground: "var(--on-accent)",
          colorBackground: "var(--surface)",
          colorForeground: "var(--ink)",
          colorMutedForeground: "var(--ink-2)",
          colorInput: "var(--bg)",
          colorInputForeground: "var(--ink)",
          colorNeutral: "var(--ink)",
          colorDanger: "var(--denied)",
          borderRadius: "7px",
          fontFamily:
            '-apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif',
        },
      }}
    >
      {page}
    </ClerkProvider>
  );
}
