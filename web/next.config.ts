import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Allow an isolated build directory so `next build` never races a running
  // `next dev`/`next start` (they share `.next`, which corrupts the build).
  // Normal runs keep the default.
  distDir: process.env.NEXT_DIST_DIR || ".next",
  // The Go control plane is reached only from the server (route handlers and
  // server components); the browser never talks to it directly.
  env: {},
};

export default nextConfig;
