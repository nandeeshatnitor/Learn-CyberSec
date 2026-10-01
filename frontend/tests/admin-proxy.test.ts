import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("next/headers", () => ({
  headers: async () => ({
    get: (name: string) => (name === "x-forwarded-for" ? "203.0.113.7" : null),
  }),
}));

import { GET as labsGet, POST as labsPost } from "@/app/api/admin/labs/[[...path]]/route";
import {
  DELETE as sessionDelete,
  GET as sessionGet,
  POST as sessionPost,
} from "@/app/api/admin/session/route";
import { ADMIN_COOKIE } from "@/lib/admin-proxy";

const ID = "33333333-3333-4333-8333-333333333333";
const TOKEN = "reviewer-token-0123456789abcdefghijkl";
const same = {
  "Sec-Fetch-Site": "same-origin",
  "Content-Type": "application/json",
  Host: "localhost:3000",
};
const signedIn = { ...same, Cookie: `${ADMIN_COOKIE}=${TOKEN}` };
const ctx = (path?: string[]) => ({ params: Promise.resolve({ path }) });
const req = (
  path: string,
  init: { method?: string; headers?: Record<string, string>; body?: string } = {},
) => new NextRequest(`http://localhost:3000/api/admin/labs${path}`, init);
const sessionReq = (
  init: { method?: string; headers?: Record<string, string>; body?: string } = {},
) => new NextRequest("http://localhost:3000/api/admin/session", init);

function upstream(status: number, body: unknown, headers: Record<string, string> = {}) {
  const fn = vi.fn(
    async () =>
      new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers }),
  );
  vi.stubGlobal("fetch", fn);
  return fn;
}
const call = (fn: ReturnType<typeof upstream>, n = 0) =>
  fn.mock.calls[n] as unknown as [string, RequestInit];

beforeEach(() => {
  process.env.BACKEND_URL = "http://backend.internal:8000/";
});
afterEach(() => vi.unstubAllGlobals());

describe("reviewer API proxy", () => {
  it.each([
    ["GET", "/whoami", ["whoami"]],
    ["GET", "/candidates", ["candidates"]],
    ["POST", "/candidates", ["candidates"]],
    ["GET", `/candidates/${ID}`, ["candidates", ID]],
    ["POST", `/candidates/${ID}/approve`, ["candidates", ID, "approve"]],
    ["POST", `/candidates/${ID}/reject`, ["candidates", ID, "reject"]],
    ["POST", `/candidates/${ID}/request-changes`, ["candidates", ID, "request-changes"]],
    ["POST", `/candidates/${ID}/regenerate`, ["candidates", ID, "regenerate"]],
    ["POST", `/candidates/${ID}/rebuild`, ["candidates", ID, "rebuild"]],
    ["POST", `/candidates/${ID}/release`, ["candidates", ID, "release"]],
    ["GET", "/versions", ["versions"]],
    ["POST", `/versions/${ID}/withdraw`, ["versions", ID, "withdraw"]],
  ])("forwards %s %s with the reviewer's token from the cookie", async (method, path, segments) => {
    const fn = upstream(200, { ok: true });
    const response = await (method === "GET" ? labsGet : labsPost)(
      req(path, { method, headers: signedIn, body: method === "POST" ? "{}" : undefined }),
      ctx(segments),
    );
    expect(response.status).toBe(200);
    const [url, init] = call(fn);
    expect(url).toBe(`http://backend.internal:8000/api/admin/labs${path}`);
    const sent = init.headers as Record<string, string>;
    expect(sent["X-Admin-Token"]).toBe(TOKEN);
    expect(sent["X-Forwarded-For"]).toBe("203.0.113.7");
    expect(Object.keys(sent).map((k) => k.toLowerCase())).not.toContain("cookie");
  });

  it.each([
    ["GET", ["candidates", "x"]],
    ["GET", ["candidates", `${ID}`, "approve"]], // wrong method
    ["POST", ["candidates", ID]],
    ["POST", ["candidates", ID, "delete"]],
    ["POST", ["candidates", ID, "publish"]],
    ["POST", ["whoami"]],
    ["GET", ["versions", ID]],
    ["POST", ["versions", ID, "edit"]],
    ["GET", ["../session"]],
    ["GET", ["candidates", ID + "x"]],
    ["GET", []],
  ])("does not forward %s %j", async (method, segments) => {
    const fn = upstream(200, {});
    const response = await (method === "GET" ? labsGet : labsPost)(
      req("/x", { method, headers: signedIn, body: method === "POST" ? "{}" : undefined }),
      ctx(segments),
    );
    expect(response.status).toBe(404);
    expect(fn).not.toHaveBeenCalled();
  });

  it("answers 401 without a cookie, or with a malformed one, and does not call the backend", async () => {
    const fn = upstream(200, {});
    expect((await labsGet(req("/candidates", { headers: same }), ctx(["candidates"]))).status).toBe(
      401,
    );
    const bad = { ...same, Cookie: `${ADMIN_COOKIE}=bad value;` };
    expect((await labsGet(req("/candidates", { headers: bad }), ctx(["candidates"]))).status).toBe(
      401,
    );
    expect(fn).not.toHaveBeenCalled();
  });

  it("refuses a cross-site state change and a request with no origin information", async () => {
    const fn = upstream(200, {});
    const cross = await labsPost(
      req(`/candidates/${ID}/approve`, {
        method: "POST",
        headers: { ...signedIn, "Sec-Fetch-Site": "cross-site" },
        body: "{}",
      }),
      ctx(["candidates", ID, "approve"]),
    );
    expect(cross.status).toBe(403);
    const none = await labsPost(
      req(`/candidates/${ID}/approve`, {
        method: "POST",
        headers: { Cookie: `${ADMIN_COOKIE}=${TOKEN}` },
        body: "{}",
      }),
      ctx(["candidates", ID, "approve"]),
    );
    expect(none.status).toBe(403);
    expect(fn).not.toHaveBeenCalled();
  });

  it("rejects bodies that are not small JSON objects", async () => {
    const fn = upstream(200, {});
    for (const body of ["not json", "[1]", "null", JSON.stringify({ notes: "x".repeat(30_000) })]) {
      const response = await labsPost(
        req(`/candidates/${ID}/approve`, { method: "POST", headers: signedIn, body }),
        ctx(["candidates", ID, "approve"]),
      );
      expect(response.status).toBe(422);
    }
    expect(fn).not.toHaveBeenCalled();
  });

  it("forwards only recognised list filters", async () => {
    const fn = upstream(200, { candidates: [] });
    await labsGet(
      req("/candidates?status=awaiting_review&cve_id=cve-2099-12345&evil=1&status2=x", {
        headers: signedIn,
      }),
      ctx(["candidates"]),
    );
    expect(call(fn)[0]).toBe(
      "http://backend.internal:8000/api/admin/labs/candidates?status=awaiting_review&cve_id=cve-2099-12345",
    );
    await labsGet(
      req("/candidates?status=bogus&cve_id=x;drop", { headers: signedIn }),
      ctx(["candidates"]),
    );
    expect(call(fn, 1)[0]).toBe("http://backend.internal:8000/api/admin/labs/candidates");
  });

  it("passes a body to the backend as a plain JSON object", async () => {
    const fn = upstream(202, { id: ID });
    await labsPost(
      req("/candidates", {
        method: "POST",
        headers: signedIn,
        body: JSON.stringify({ cve_id: "CVE-2099-12345", overrides: {} }),
      }),
      ctx(["candidates"]),
    );
    expect(JSON.parse(call(fn)[1].body as string)).toEqual({
      cve_id: "CVE-2099-12345",
      overrides: {},
    });
  });

  it("lets the documented error statuses through with fixed fields, and hides anything else", async () => {
    upstream(409, {
      error: {
        code: "conflict",
        message: "Cannot approve: nope.",
        request_id: "r",
        trace: "/app/secret.py",
      },
    });
    const conflict = await labsPost(
      req(`/candidates/${ID}/approve`, { method: "POST", headers: signedIn, body: "{}" }),
      ctx(["candidates", ID, "approve"]),
    );
    expect(conflict.status).toBe(409);
    expect(await conflict.json()).toEqual({
      error: { code: "conflict", message: "Cannot approve: nope." },
    });
    upstream(500, "<html>traceback /home/app/secret.py</html>");
    const hidden = await labsGet(req("/candidates", { headers: signedIn }), ctx(["candidates"]));
    expect(hidden.status).toBe(503);
    expect(await hidden.text()).not.toMatch(/traceback|secret/);
  });

  it("drops the cookie when the backend no longer accepts the token", async () => {
    upstream(401, {
      error: { code: "unauthorized", message: "A valid reviewer token is required." },
    });
    const response = await labsGet(req("/candidates", { headers: signedIn }), ctx(["candidates"]));
    expect(response.status).toBe(401);
    expect(response.cookies.get(ADMIN_COOKIE)?.value ?? "").toBe("");
  });

  it("turns an unreachable backend into a plain 503", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("ECONNREFUSED 10.0.0.5:8000");
    });
    const response = await labsGet(req("/candidates", { headers: signedIn }), ctx(["candidates"]));
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("10.0.0.5");
  });

  it("never sets a cookie of its own on ordinary calls", async () => {
    upstream(200, { candidates: [] });
    const response = await labsGet(req("/candidates", { headers: signedIn }), ctx(["candidates"]));
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});

describe("reviewer session", () => {
  it("signs in by verifying the token with the backend, then keeps it in an HttpOnly strict cookie", async () => {
    const fn = upstream(200, { name: "alice", labgen_enabled: true });
    const response = await sessionPost(
      sessionReq({ method: "POST", headers: same, body: JSON.stringify({ token: ` ${TOKEN} ` }) }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ name: "alice", labgen_enabled: true });
    expect(call(fn)[0]).toBe("http://backend.internal:8000/api/admin/labs/whoami");
    expect((call(fn)[1].headers as Record<string, string>)["X-Admin-Token"]).toBe(TOKEN);
    const cookie = response.headers.get("set-cookie") ?? "";
    expect(cookie).toContain(`${ADMIN_COOKIE}=${TOKEN}`);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=strict/i);
    expect(cookie).toMatch(/Max-Age=\d+/i);
  });

  it("marks the cookie Secure behind https", async () => {
    upstream(200, { name: "alice", labgen_enabled: true });
    const response = await sessionPost(
      sessionReq({
        method: "POST",
        headers: { ...same, "x-forwarded-proto": "https" },
        body: JSON.stringify({ token: TOKEN }),
      }),
    );
    expect(response.headers.get("set-cookie")).toMatch(/Secure/i);
  });

  it("does not store a token the backend rejects", async () => {
    upstream(401, {
      error: { code: "unauthorized", message: "A valid reviewer token is required." },
    });
    const response = await sessionPost(
      sessionReq({ method: "POST", headers: same, body: JSON.stringify({ token: TOKEN }) }),
    );
    expect(response.status).toBe(401);
    expect(response.headers.get("set-cookie") ?? "").not.toContain(TOKEN);
  });

  it.each([
    {},
    { token: "short" },
    { token: 12345 },
    { token: "has spaces in the token 0123456789" },
  ])("refuses %j without calling the backend", async (body) => {
    const fn = upstream(200, {});
    const response = await sessionPost(
      sessionReq({ method: "POST", headers: same, body: JSON.stringify(body) }),
    );
    expect(response.status).toBe(401);
    expect(fn).not.toHaveBeenCalled();
  });

  it("refuses a cross-site sign-in or sign-out", async () => {
    const fn = upstream(200, {});
    const cross = { ...same, "Sec-Fetch-Site": "cross-site" };
    expect(
      (
        await sessionPost(
          sessionReq({ method: "POST", headers: cross, body: JSON.stringify({ token: TOKEN }) }),
        )
      ).status,
    ).toBe(403);
    expect((await sessionDelete(sessionReq({ method: "DELETE", headers: cross }))).status).toBe(
      403,
    );
    expect(fn).not.toHaveBeenCalled();
  });

  it("signing out clears the cookie", async () => {
    const response = await sessionDelete(sessionReq({ method: "DELETE", headers: signedIn }));
    expect(response.status).toBe(200);
    expect(response.cookies.get(ADMIN_COOKIE)?.value ?? "").toBe("");
  });

  it("reports who is signed in, or 401 when nobody is", async () => {
    upstream(200, { name: "alice", labgen_enabled: true });
    const ok = await sessionGet(sessionReq({ headers: signedIn }));
    expect(ok.status).toBe(200);
    const none = await sessionGet(sessionReq({ headers: same }));
    expect(none.status).toBe(401);
  });
});
