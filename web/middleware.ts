import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import { NextResponse } from "next/server";
import { clerkConfigured } from "@/lib/auth";

// Public surface: marketing page and Clerk's hosted auth routes.
const isPublic = createRouteMatcher(["/", "/login(.*)", "/signup(.*)"]);

const withClerk = clerkMiddleware(async (auth, req) => {
  if (isPublic(req)) return;

  const { userId } = await auth();
  if (userId) return;

  // Explicit redirect. `auth.protect()` returns a 404 when it has no sign-in
  // URL to resolve, which is not what we want for a gated dashboard.
  const url = new URL("/login", req.url);
  url.searchParams.set("redirect_url", req.url);
  return NextResponse.redirect(url);
});

// Without keys the app still builds and renders; the auth pages explain what to add.
const passthrough = () => NextResponse.next();

export default clerkConfigured ? withClerk : passthrough;

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)",
  ],
};
