import { NextRequest } from "next/server";
import { afterEach, describe, expect, it } from "vitest";

import { contentSecurityPolicy, terminalOrigin } from "@/lib/csp";
import { proxy } from "@/proxy";

afterEach(() => {
  delete process.env.TERMINAL_WS_ORIGIN;
});

const run = (path: string) => proxy(new NextRequest(`http://localhost:3000${path}`));

describe("contentSecurityPolicy", () => {
  it("locks everything to this site by default", () => {
    const csp = contentSecurityPolicy({ dev: false });
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("unsafe-eval");
  });
  it("adds only the named terminal origin to connect-src", () => {
    expect(contentSecurityPolicy({ dev: false, connect: ["wss://labs.example.com"] })).toContain("connect-src 'self' wss://labs.example.com;");
  });
  it.each([
    ["wss://labs.example.com", "wss://labs.example.com"],
    ["ws://localhost:8000", "ws://localhost:8000"],
    ["https://labs.example.com", null],
    ["wss://labs.example.com/path", null],
    ["wss://evil.example.com; script-src *", null],
    ["ws://a b", null],
    ["*", null],
    ["", null],
    [undefined, null],
  ])("terminalOrigin(%j)", (value, expected) => {
    expect(terminalOrigin(value)).toBe(expected);
  });
});

describe("lab page headers (proxy)", () => {
  it("names the terminal gateway origin, read at runtime, only on lab pages", () => {
    process.env.TERMINAL_WS_ORIGIN = "wss://labs.example.com";
    const csp = run("/lab/22222222-2222-4222-8222-222222222222").headers.get("content-security-policy");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("wss://labs.example.com");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(run("/lab/x").headers.get("x-frame-options")).toBe("DENY");
    expect(run("/lab/x").headers.get("x-content-type-options")).toBe("nosniff");
    expect(run("/learn/CVE-2099-12345").headers.get("content-security-policy")).toBeNull(); // next.config covers these
  });

  it("ignores an invalid TERMINAL_WS_ORIGIN instead of widening the policy", () => {
    process.env.TERMINAL_WS_ORIGIN = "wss://evil.example.com; script-src *";
    const csp = run("/lab/x").headers.get("content-security-policy")!;
    expect(csp).not.toContain("evil");
    expect(csp).toMatch(/connect-src 'self'( ws:)?;/); // (`ws:` is the dev-server allowance)
  });

  it("does not touch the headers of the lab's own app (the backend sets them)", () => {
    const response = run("/lab-app/22222222-2222-4222-8222-222222222222/tokentokentokentoken0123/");
    expect(response.headers.get("content-security-policy")).toBeNull();
    expect(response.headers.get("x-frame-options")).toBeNull();
  });
});

describe("malformed percent-encoding is answered by a normal not-found path", () => {
  it.each([
    ["/lab/%E0%A4%A", "/lab/invalid"],
    ["/lab-app/%E0%A4%A/x", "/lab-app/invalid/invalid"],
    ["/api/sandbox/instances/%E0%A4%A", "/api/sandbox/invalid"],
  ])("%s", (path, target) => {
    expect(run(path).headers.get("x-middleware-rewrite")).toContain(target);
  });
});
