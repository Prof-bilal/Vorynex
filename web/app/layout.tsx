import type { Metadata, Viewport } from "next";
import { ClerkProvider } from "@clerk/nextjs";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "Vorynex — Runtime containment for web apps",
    template: "%s · Vorynex",
  },
  description:
    "Vorynex learns what your web app needs, enforces a least-privilege runtime boundary, and contains post-exploitation behavior. The app can still have bugs. Vorynex makes exploiting them a dead end.",
};

export const viewport: Viewport = {
  colorScheme: "dark",
  themeColor: "#08090a",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <ClerkProvider
      appearance={{
        variables: {
          colorPrimary: "#5eead4",
          colorPrimaryForeground: "#08090a",
          colorBackground: "#0e0f11",
          colorForeground: "#f7f8f8",
          colorMutedForeground: "#a8adb5",
          colorInput: "#121316",
          colorInputForeground: "#f7f8f8",
          colorNeutral: "#f7f8f8",
          colorDanger: "#ff8677",
          borderRadius: "10px",
          fontFamily:
            '-apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif',
        },
      }}
    >
      <html lang="en">
        <body>{children}</body>
      </html>
    </ClerkProvider>
  );
}
