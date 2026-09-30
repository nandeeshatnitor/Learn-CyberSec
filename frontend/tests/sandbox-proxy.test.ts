import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("next/headers", () => ({ headers: async () => ({ get: (name: string) => (name === "x-forwarded-for" ? "203.0.113.7" : null) }) }));

import { GET as apiGet, POST as apiPost } from "@/app/api/sandbox/[[...path]]/route";
import { GET as appGet, HEAD as appHead, POST as appPost } from "@/app/lab-app/[instanceId]/[token]/[[...rest]]/route";
import { LEARNER_COOKIE } from "@/lib/learning-proxy";

const IID = "22222222-2222-4222-8222-222222222222";
const TOKEN = "tokentokentokentoken0123";
const LEARNER = "abcdefghijklmnopqrstuvwxyz012345";
const sameOrigin = { "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json", Host: "localhost:3000", Cookie: `${LEARNER_COOKIE}=${LEARNER}` };
const apiCtx = (path?: string[]) => ({ params: Promise.resolve({ path }) });
const appCtx = (instanceId = IID, token = TOKEN) => ({ params: Promise.resolve({ instanceId, token }) });

function upstream(status: number, body: unknown, headers: Record<string, string> = {}) {
  const empty = [204, 205, 304].includes(status);
  const fn = vi.fn(async () => new Response(empty ? null : typeof body === "string" || body instanceof Uint8Array ? (body as BodyInit) : JSON.stringify(body), { status, headers }));
  vi.stubGlobal("fetch", fn);
  return fn;
}
const call = (fn: ReturnType<typeof upstream>, n = 0) => fn.mock.calls[n] as unknown as [string, RequestInit];
const api = (path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) =>
  new NextRequest(`http://localhost:3000/api/sandbox${path}`, init);
const app = (path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) =>
  new NextRequest(`http://localhost:3000/lab-app/${IID}/${TOKEN}${path}`, init);

beforeEach(() => {
  process.env.BACKEND_URL = "http://backend.internal:8000/";
});
afterEach(() => vi.unstubAllGlobals());

describe("sandbox JSON proxy", () => {
  it.each([
    ["GET", "/labs", ["labs"]],
    ["GET", "/labs/path-traversal-101", ["labs", "path-traversal-101"]],
    ["GET", "/instances/current", ["instances", "current"]],
    ["GET", `/instances/${IID}`, ["instances", IID]],
    ["GET", `/sessions/${IID}/labs`, ["sessions", IID, "labs"]],
    ["POST", "/instances", ["instances"]],
    ["POST", `/instances/${IID}/reset`, ["instances", IID, "reset"]],
    ["POST", `/instances/${IID}/stop`, ["instances", IID, "stop"]],
    ["POST", `/instances/${IID}/verify`, ["instances", IID, "verify"]],
    ["POST", `/instances/${IID}/network-check`, ["instances", IID, "network-check"]],
    ["POST", `/instances/${IID}/terminal-ticket`, ["instances", IID, "terminal-ticket"]],
  ])("forwards %s %s to the backend on behalf of the learner", async (method, path, segments) => {
    const fn = upstream(200, { ok: true });
    const request = api(path, { method, headers: sameOrigin, body: method === "POST" ? "{}" : undefined });
    const response = await (method === "GET" ? apiGet : apiPost)(request, apiCtx(segments));
    expect(response.status).toBe(200);
    const [url, init] = call(fn);
    expect(url).toBe(`http://backend.internal:8000/api/sandbox${path}`);
    expect((init.headers as Record<string, string>)["X-Learner-Token"]).toBe(LEARNER);
  });

  it.each([
    ["GET", ["instances"]],  // wrong method
    ["POST", ["labs"]],
    ["GET", ["terminal", "ws"]],
    ["GET", ["app", IID, TOKEN, "x"]],
    ["POST", ["instances", IID, "delete"]],
    ["POST", ["instances", "current"]],
    ["GET", ["instances", "../etc"]],
    ["GET", ["labs", "UPPER"]],
    ["GET", ["sessions", "x", "labs"]],
    ["GET", ["instances", IID, "reset"]],
    ["GET", ["instances", IID + "x"]],
  ])("does not forward %s %j", async (method, segments) => {
    const fn = upstream(200, {});
    const response = await (method === "GET" ? apiGet : apiPost)(api("/x", { method, headers: sameOrigin, body: method === "POST" ? "{}" : undefined }), apiCtx(segments));
    expect(response.status).toBe(404);
    expect(fn).not.toHaveBeenCalled();
  });

  it("refuses a cross-site state change", async () => {
    const fn = upstream(200, {});
    const response = await apiPost(api(`/instances/${IID}/reset`, { method: "POST", headers: { ...sameOrigin, "Sec-Fetch-Site": "cross-site" }, body: "{}" }), apiCtx(["instances", IID, "reset"]));
    expect(response.status).toBe(403);
    expect(fn).not.toHaveBeenCalled();
  });

  it("issues the learner cookie on first use, HttpOnly", async () => {
    upstream(200, { instance: null });
    const response = await apiGet(api("/instances/current"), apiCtx(["instances", "current"]));
    expect(response.headers.get("set-cookie")).toMatch(/HttpOnly/i);
    expect(response.cookies.get(LEARNER_COOKIE)?.value).toMatch(/^[A-Za-z0-9_-]{32}$/);
  });

  it("lets the lab error statuses through with fixed fields, and hides anything else", async () => {
    upstream(502, { error: { code: "lab_start_failed", message: "The lab could not be started.", request_id: "x", detail: "docker: secret" } });
    const bad = await apiPost(api("/instances", { method: "POST", headers: sameOrigin, body: "{}" }), apiCtx(["instances"]));
    expect(bad.status).toBe(502);
    expect(await bad.json()).toEqual({ error: { code: "lab_start_failed", message: "The lab could not be started." } });
    upstream(500, "<html>traceback: /home/app/secret.py</html>");
    const hidden = await apiGet(api("/labs"), apiCtx(["labs"]));
    expect(hidden.status).toBe(503);
    expect(await hidden.text()).not.toMatch(/traceback|secret/);
  });

  it("turns an unreachable backend into a plain 503", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("ECONNREFUSED 10.0.0.5:8000");
    });
    const response = await apiGet(api("/labs"), apiCtx(["labs"]));
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("10.0.0.5");
  });
});

describe("lab app proxy", () => {
  it("passes the path and query exactly as the browser sent them, dot-dot segments and encoding included", async () => {
    const fn = upstream(200, "the secret", { "content-type": "text/plain" });
    const response = await appGet(app("/download?name=../private/canary.txt&x=%2e%2e%2f"), appCtx());
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("the secret");
    expect(call(fn)[0]).toBe(`http://backend.internal:8000/api/sandbox/app/${IID}/${TOKEN}/download?name=../private/canary.txt&x=%2e%2e%2f`);
  });

  it("keeps percent-encoded path segments encoded", async () => {
    const fn = upstream(200, "x");
    await appGet(app("/a%2Fb/c%20d"), appCtx());
    expect(call(fn)[0]).toBe(`http://backend.internal:8000/api/sandbox/app/${IID}/${TOKEN}/a%2Fb/c%20d`);
  });

  it("serves the app root, with or without the trailing slash", async () => {
    const fn = upstream(200, "home");
    await appGet(app("/"), appCtx());
    await appGet(app(""), appCtx());
    expect(call(fn, 0)[0]).toBe(`http://backend.internal:8000/api/sandbox/app/${IID}/${TOKEN}/`);
    expect(call(fn, 1)[0]).toBe(`http://backend.internal:8000/api/sandbox/app/${IID}/${TOKEN}/`);
  });

  it("tells the backend which prefix it lives under, for link rewriting", async () => {
    const fn = upstream(200, "x");
    await appGet(app("/"), appCtx());
    expect((call(fn)[1].headers as Record<string, string>)["X-Lab-Prefix"]).toBe(`/lab-app/${IID}/${TOKEN}`);
  });

  it("never forwards the learner's cookie or credentials into the lab", async () => {
    const fn = upstream(200, "x");
    await appGet(app("/", { headers: { Cookie: `${LEARNER_COOKIE}=${LEARNER}`, Authorization: "Bearer x", "X-Learner-Token": LEARNER, Accept: "text/html", "Accept-Language": "en" } }), appCtx());
    const sent = call(fn)[1].headers as Record<string, string>;
    expect(Object.keys(sent).map((k) => k.toLowerCase()).sort()).toEqual(["accept", "accept-language", "x-forwarded-for", "x-lab-prefix"]);
    expect(JSON.stringify(sent)).not.toContain(LEARNER);
  });

  it("needs no learner cookie: the URL is the credential", async () => {
    upstream(200, "x");
    const response = await appGet(app("/"), appCtx());
    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toBeNull();
  });

  it("passes on only a fixed set of response headers, including the sandboxing ones", async () => {
    upstream(200, "<h1>hi</h1>", {
      "content-type": "text/html", "content-security-policy": "sandbox allow-scripts allow-forms; frame-ancestors 'self'",
      "x-content-type-options": "nosniff", "set-cookie": "evil=1", "access-control-allow-origin": "*", "x-powered-by": "evil", server: "evil",
    });
    const response = await appGet(app("/"), appCtx());
    expect(response.headers.get("content-security-policy")).toContain("sandbox");
    expect(response.headers.get("content-security-policy")).not.toContain("allow-same-origin");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("cache-control")).toBe("no-store");
    for (const name of ["set-cookie", "access-control-allow-origin", "x-powered-by", "server"]) expect(response.headers.get(name)).toBeNull();
  });

  it("relays redirects without following them", async () => {
    const fn = upstream(302, "", { location: "/lab-app/x/y/download" });
    const response = await appGet(app("/go"), appCtx());
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/lab-app/x/y/download");
    expect(call(fn)[1].redirect).toBe("manual");
  });

  it("forwards a POST body, capped", async () => {
    const fn = upstream(200, "ok");
    await appPost(app("/form", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "a=1&b=2" }), appCtx());
    const init = call(fn)[1];
    expect(init.method).toBe("POST");
    expect(new TextDecoder().decode(init.body as ArrayBuffer)).toBe("a=1&b=2");
    const big = await appPost(app("/form", { method: "POST", body: "x".repeat(70_000) }), appCtx());
    expect(big.status).toBe(413);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("answers HEAD without a body", async () => {
    upstream(200, "body");
    const response = await appHead(app("/health", { method: "HEAD" }), appCtx());
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("");
  });

  it("does not try to send a body with 204 or 304 answers", async () => {
    upstream(204, "");
    expect((await appGet(app("/x"), appCtx())).status).toBe(204);
  });

  it.each([
    [{ instanceId: "not-a-uuid", token: TOKEN }],
    [{ instanceId: IID, token: "short" }],
    [{ instanceId: IID, token: "tok/en/tok/en/tok/en" }],
    [{ instanceId: "../..", token: TOKEN }],
  ])("refuses malformed identifiers %j before calling the backend", async ({ instanceId, token }) => {
    const fn = upstream(200, "x");
    const response = await appGet(app("/"), appCtx(instanceId, token));
    expect(response.status).toBe(404);
    expect(fn).not.toHaveBeenCalled();
  });

  it("refuses a request whose URL does not match its own capability", async () => {
    const fn = upstream(200, "x");
    const other = new NextRequest(`http://localhost:3000/lab-app/33333333-3333-4333-8333-333333333333/${TOKEN}/`);
    expect((await appGet(other, appCtx())).status).toBe(404);
    expect(fn).not.toHaveBeenCalled();
  });

  it("reports an unreachable backend or a nonsense status without leaking details", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("connect ECONNREFUSED 10.200.4.2:8080");
    });
    const down = await appGet(app("/"), appCtx());
    expect(down.status).toBe(502);
    expect(await down.text()).not.toContain("10.200");
    upstream(101, "");
    expect((await appGet(app("/"), appCtx())).status).toBe(502);
  });
});
