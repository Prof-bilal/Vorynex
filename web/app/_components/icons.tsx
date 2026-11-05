type IconProps = { size?: number };

/* Thin monochrome line icons for feature cells (Tailscale-style restraint). */
function Line({ size = 20, children }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

export function ShieldIcon({ size = 20 }: IconProps) {
  return (
    <Line size={size}>
      <path d="M12 3l7 3v5.5c0 4.2-2.9 7.6-7 9.5-4.1-1.9-7-5.3-7-9.5V6l7-3z" />
      <path d="M9 12.2l2 2 4-4.2" />
    </Line>
  );
}

export function TerminalIcon({ size = 20 }: IconProps) {
  return (
    <Line size={size}>
      <rect x="3" y="4" width="18" height="16" rx="2.5" />
      <path d="M7.5 10l2.2 2-2.2 2M12.5 14h4" />
    </Line>
  );
}

export function NetworkIcon({ size = 20 }: IconProps) {
  return (
    <Line size={size}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M3.5 12h17M12 3.5c2.4 2.4 3.6 5.4 3.6 8.5S14.4 18.1 12 20.5c-2.4-2.4-3.6-5.4-3.6-8.5S9.6 5.9 12 3.5z" />
    </Line>
  );
}

export function KeyIcon({ size = 20 }: IconProps) {
  return (
    <Line size={size}>
      <circle cx="8" cy="12" r="3.6" />
      <path d="M11.4 12H20M17.4 12v2.6M14.6 12v2.2" />
    </Line>
  );
}

export function KernelIcon({ size = 20 }: IconProps) {
  return (
    <Line size={size}>
      <rect x="8.5" y="8.5" width="7" height="7" rx="1.6" />
      <path d="M12 3v5.5M12 15.5V21M3 12h5.5M15.5 12H21M5.6 5.6l3.4 3.4M15 15l3.4 3.4M18.4 5.6L15 9M9 15l-3.4 3.4" />
    </Line>
  );
}

export function EyeIcon({ size = 20 }: IconProps) {
  return (
    <Line size={size}>
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12S18 18.5 12 18.5 2.5 12 2.5 12z" />
      <circle cx="12" cy="12" r="3" />
    </Line>
  );
}

export function GitHubIcon({ size = 16 }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false">
      <path d="M12 .5C5.73.5.5 5.74.5 12.02c0 5.02 3.29 9.29 7.86 10.75.57.1.78-.25.78-.55v-2.1c-3.2.7-3.88-1.4-3.88-1.4-.53-1.35-1.3-1.71-1.3-1.71-1.06-.72.08-.7.08-.7 1.17.08 1.79 1.2 1.79 1.2 1.04 1.79 2.73 1.27 3.4.97.1-.76.4-1.27.73-1.56-2.55-.29-5.24-1.28-5.24-5.7 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.79 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.24 2.76.12 3.05.74.81 1.18 1.84 1.18 3.1 0 4.43-2.69 5.4-5.26 5.69.41.36.78 1.06.78 2.14v3.17c0 .3.2.66.79.55A11.53 11.53 0 0 0 23.5 12C23.5 5.74 18.27.5 12 .5Z" />
    </svg>
  );
}

export function GoogleIcon({ size = 16 }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" aria-hidden="true" focusable="false">
      <path
        fill="#EA4335"
        d="M24 9.5c3.54 0 6.7 1.22 9.19 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5Z"
      />
      <path
        fill="#4285F4"
        d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65Z"
      />
      <path
        fill="#FBBC05"
        d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24s.92 7.54 2.55 10.78l7.98-6.19Z"
      />
      <path
        fill="#34A853"
        d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48Z"
      />
    </svg>
  );
}
