"use client";

import { SignOutButton as ClerkSignOutButton } from "@clerk/nextjs";

export default function SignOutButton() {
  if (!process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY) return null;
  return (
    <ClerkSignOutButton redirectUrl="/">
      <button className="btn btn-ghost btn-sm" type="button">
        Sign out
      </button>
    </ClerkSignOutButton>
  );
}
