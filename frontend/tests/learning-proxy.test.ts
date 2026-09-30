import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let forwarded: string | null = "203.0.113.7";
vi.mock("next/headers", () => ({
  headers: async () => ({ get: (name: string) => (name === "x-forwarded-for" ? forwarded : null) }),
}));

import { GET, POST } from "@/app/api/learning/[[...path]]/route";
import { LEARNER_COOKIE, newLearnerToken } from "@/lib/learning-proxy";

const SID = "11111111-1111-4111-8111-111111111111";
const ctx = (path?: string[]) => ({ params: Promise.resolve({ path }) });
const sameOrigin = { "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json", Host: "localhost:3000" };
const TOKEN = "abcdefghijklmnopqrstuvwxyz012345";

function req(path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) {
  return new NextRequest(`http://localhost:3000/api/learning${path}`, init);
}
function backend(status: number, body: unknown, headers: Record<string, string> = {}) {
  const fn = vi.fn(async () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers }));
  vi.stubGlobal("fetch", fn);
  return fn;
}
const upstream = (fn: ReturnType<typeof backend>, n = 0) => fn.mock.calls[n] as unknown as [string, RequestInit];

beforeEach(() => {
  forwarded = "203.0.113.7";
  process.env.BACKEND_URL = "http://backend.internal:8000/";
});
afterEach(() => vi.unstubAllGlobals());

describe("learning proxy: identity", () => {
  it("issues an HttpOnly, SameSite cookie on first use and forwards its token in a header", async () => {
    const fn = backend(200, { id: SID });
    const response = await GET(req(`/${SID}`), ctx([SID]));
    const cookie = response.cookies.get(LEARNER_COOKIE);
    expect(cookie?.value).toMatch(/^[A-Za-z0-9_-]{32}$/);
    const header = response.headers.get("set-cookie") ?? "";
    expect(header).toMatch(/HttpOnly/i);
    expect(header).toMatch(/SameSite=lax/i);
    expect(header).toMatch(/Path=\//);
    expect((upstream(fn)[1].headers as Record<string, string>)["X-Learner-Token"]).toBe(cookie?.value);
    expect(await response.text()).not.toContain(cookie!.value); // never echoed in the body
  });

  it("reuses a valid cookie without setting a new one, and replaces a malformed one", async () => {
    const fn = backend(200, { id: SID });
    const reused = await GET(req(`/${SID}`, { headers: { Cookie: `${LEARNER_COOKIE}=${TOKEN}` } }), ctx([SID]));
    expect(reused.cookies.get(LEARNER_COOKIE)).toBeUndefined();
    expect((upstream(fn)[1].headers as Record<string, string>)["X-Learner-Token"]).toBe(TOKEN);

    const replaced = await GET(req(`/${SID}`, { headers: { Cookie: `${LEARNER_COOKIE}=bad value<script>` } }), ctx([SID]));
    expect(replaced.cookies.get(LEARNER_COOKIE)?.value).toMatch(/^[A-Za-z0-9_-]{32}$/);
  });

  it("marks the cookie Secure behind https", async () => {
    backend(200, { id: SID });
    const response = await GET(req(`/${SID}`, { headers: { "x-forwarded-proto": "https" } }), ctx([SID]));
    expect(response.headers.get("set-cookie")).toMatch(/Secure/i);
  });

  it("generates unguessable tokens", () => {
    const tokens = new Set(Array.from({ length: 50 }, newLearnerToken));
    expect(tokens.size).toBe(50);
    for (const t of tokens) expect(t).toMatch(/^[A-Za-z0-9_-]{32}$/);
  });

  it("forwards nothing else from the visitor", async () => {
    const fn = backend(200, { id: SID });
    await GET(
      req(`/${SID}`, { headers: { Cookie: `${LEARNER_COOKIE}=${TOKEN}; other=secret`, Authorization: "Bearer x", "X-Api-Key": "k" } }),
      ctx([SID]),
    );
    expect(upstream(fn)[1].headers).toEqual({ Accept: "application/json", "X-Learner-Token": TOKEN, "X-Forwarded-For": "203.0.113.7" });
    forwarded = "1.2.3.4\r\nX-Injected: yes";
    await GET(req(`/${SID}`), ctx([SID]));
    expect((upstream(fn, 1)[1].headers as Record<string, string>)["X-Forwarded-For"]).toBeUndefined();
  });
});

describe("learning proxy: routing", () => {
  it.each([
    ["GET", [], undefined],
    ["GET", ["by-cve", "CVE-2099-12345", "x"], undefined],
    ["GET", ["by-cve", "nope"], undefined],
    ["GET", ["..", "admin"], undefined],
    ["GET", [SID, "start"], undefined], // start is POST only
    ["GET", [SID, "tasks", "t1", "answer"], undefined], // answer is POST only
    ["POST", [SID, "tasks", "../x", "answer"], "{}"],
    ["POST", [SID, "tasks", "t1", "delete"], "{}"],
    ["POST", ["by-cve", "CVE-2099-12345"], "{}"],
    ["POST", [SID, "unknown"], "{}"],
    ["GET", ["not-a-uuid"], undefined],
    ["GET", [SID.slice(0, -1) + "%2F.."], undefined],
  ] as const)("refuses %s /%j without contacting the backend", async (method, path, body) => {
    const fn = backend(200, {});
    const handler = method === "GET" ? GET : POST;
    const response = await handler(
      req(`/${path.join("/")}`, { method, headers: sameOrigin, body: body as string | undefined }),
      ctx([...path]),
    );
    expect(response.status).toBe(404);
    expect(fn).not.toHaveBeenCalled();
  });

  it("maps allowed paths to the same backend paths", async () => {
    const cases: [string, string[], string][] = [
      ["GET", ["by-cve", "CVE-2099-12345"], "/api/learning/by-cve/CVE-2099-12345"],
      ["GET", [SID], `/api/learning/${SID}`],
      ["GET", [SID, "hints"], `/api/learning/${SID}/hints`],
      ["GET", [SID, "tutor"], `/api/learning/${SID}/tutor`],
      ["GET", [SID, "tasks", "t2", "solution"], `/api/learning/${SID}/tasks/t2/solution`],
      ["POST", [], "/api/learning"],
      ["POST", [SID, "start"], `/api/learning/${SID}/start`],
      ["POST", [SID, "complete"], `/api/learning/${SID}/complete`],
      ["POST", [SID, "hints"], `/api/learning/${SID}/hints`],
      ["POST", [SID, "tutor"], `/api/learning/${SID}/tutor`],
      ["POST", [SID, "tasks", "t1", "answer"], `/api/learning/${SID}/tasks/t1/answer`],
      ["POST", [SID, "tasks", "t1", "solution"], `/api/learning/${SID}/tasks/t1/solution`],
    ];
    for (const [method, path, expected] of cases) {
      const fn = backend(200, { ok: true });
      const handler = method === "GET" ? GET : POST;
      const response = await handler(
        req(`/${path.join("/")}`, { method, headers: sameOrigin, body: method === "POST" ? "{}" : undefined }),
        ctx(path.length ? path : undefined),
      );
      expect(response.status, `${method} ${path.join("/")}`).toBe(200);
      expect(upstream(fn)[0]).toBe(`http://backend.internal:8000${expected}`);
    }
  });
});

describe("learning proxy: requests and responses", () => {
  it("refuses cross-site and header-less POSTs", async () => {
    const fn = backend(200, {});
    const attempts: Record<string, string>[] = [
      { "Sec-Fetch-Site": "cross-site", "Content-Type": "application/json" },
      { Origin: "https://evil.example", Host: "localhost:3000" },
      {},
    ];
    for (const headers of attempts) {
      const response = await POST(req(`/${SID}/hints`, { method: "POST", headers, body: "{}" }), ctx([SID, "hints"]));
      expect(response.status).toBe(403);
    }
    expect(fn).not.toHaveBeenCalled();
  });

  it("re-serialises JSON bodies and rejects anything else", async () => {
    const fn = backend(200, { ok: true });
    await POST(req(`/${SID}/hints`, { method: "POST", headers: sameOrigin, body: ' { "task_id" : "t1", "number":1 } ' }), ctx([SID, "hints"]));
    expect(upstream(fn)[1].body).toBe('{"task_id":"t1","number":1}');
    for (const body of ["not json", "[1,2]", '"string"', "x".repeat(30_000)]) {
      const response = await POST(req(`/${SID}/hints`, { method: "POST", headers: sameOrigin, body }), ctx([SID, "hints"]));
      expect(response.status).toBe(422);
    }
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("passes safe errors through with only the fixed code and message", async () => {
    backend(409, { error: { code: "conflict", message: "Hints are revealed in order.", request_id: "x", details: [{ secret: 1 }] } }, { "Set-Cookie": "leak=1", "X-Internal": "y" });
    const response = await POST(req(`/${SID}/hints`, { method: "POST", headers: sameOrigin, body: "{}" }), ctx([SID, "hints"]));
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: { code: "conflict", message: "Hints are revealed in order." } });
    expect(response.headers.get("x-internal")).toBeNull();
    expect(response.headers.get("set-cookie")).not.toMatch(/leak/);
  });

  it("passes rate limiting through with Retry-After", async () => {
    backend(429, { error: { code: "rate_limited", message: "Slow down." } }, { "Retry-After": "90" });
    const response = await POST(req(`/${SID}/tutor`, { method: "POST", headers: sameOrigin, body: "{}" }), ctx([SID, "tutor"]));
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("90");
  });

  it("does not let unexpected upstream statuses, bodies or failures through", async () => {
    for (const [status, body] of [
      [500, { error: { message: "psycopg.OperationalError: password authentication failed" } }],
      [502, "<html>bad gateway 10.0.0.4</html>"],
      [200, "not json"],
      [200, "[1]"],
    ] as const) {
      backend(status, body);
      const response = await GET(req(`/${SID}`), ctx([SID]));
      expect(response.status).toBe(503);
      expect(await response.text()).not.toMatch(/psycopg|password|10\.0\.0\.4/);
    }
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("connect ECONNREFUSED 10.0.0.9:8000"); }));
    const down = await GET(req(`/${SID}`), ctx([SID]));
    expect(down.status).toBe(503);
    expect(await down.text()).not.toMatch(/10\.0\.0\.9|ECONNREFUSED/);
  });

  it("marks every response uncacheable", async () => {
    backend(200, { id: SID });
    const response = await GET(req(`/${SID}`), ctx([SID]));
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});
