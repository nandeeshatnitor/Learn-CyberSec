/** Content-Security-Policy builder shared by next.config.ts (most pages) and the proxy (lab pages). */
export function contentSecurityPolicy(options: { dev: boolean; connect?: string[] }): string {
  const connect = ["'self'", ...(options.dev ? ["ws:"] : []), ...(options.connect ?? [])];
  return [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline'${options.dev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src ${connect.join(" ")}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

/**
 * The origin the browser may open the terminal WebSocket to, from the server-side
 * TERMINAL_WS_ORIGIN setting (e.g. wss://labs.example.com). Anything else is ignored: an
 * invalid value must never widen the policy.
 */
export function terminalOrigin(value: string | undefined): string | null {
  return value && /^wss?:\/\/[A-Za-z0-9.-]{1,200}(:\d{1,5})?$/.test(value) ? value : null;
}

export const SECURITY_HEADERS = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];
