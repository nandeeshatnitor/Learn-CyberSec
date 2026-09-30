import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let forwarded: string | null = "203.0.113.7";
vi.mock("next/headers", () => ({
  // A bare object: a real Headers would refuse the malformed value these tests feed in.
  headers: async () => ({ get: (name: string) => (name === "x-forwarded-for" ? forwarded : null) }),
}));

import { GET as getGuide, POST as startResearch } from "@/app/api/cves/[cveId]/research/route";
import { GET as getStatus } from "@/app/api/cves/[cveId]/research/status/route";

const ID = "CVE-2099-12345";
const ctx = (cveId: string) => ({ params: Promise.resolve({ cveId }) });

function req(path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) {
  return new NextRequest(`http://localhost:3000${path}`, init);
}
const sameOrigin = { "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json", Host: "localhost:3000" };

function backend(status: number, body: unknown, headers: Record<string, string> = {}) {
  const fn = vi.fn(async () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers }));
  vi.stubGlobal("fetch", fn);
  return fn;
}

beforeEach(() => {
  forwarded = "203.0.113.7";
  process.env.BACKEND_URL = "http://backend.internal:8000/";
});
afterEach(() => vi.unstubAllGlobals());

describe("research route handlers", () => {
  it("proxies the status to the backend and returns its JSON", async () => {
    const fetchMock = backend(200, { cve_id: ID, status: "queued" });
    const response = await getStatus(req(`/api/cves/${ID}/research/status`), ctx(ID));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ cve_id: ID, status: "queued" });
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`http://backend.internal:8000/api/cves/${ID}/research/status`);
    expect(init.method).toBeUndefined();
  });

  it("proxies the stored guide", async () => {
    const fetchMock = backend(200, { cve_id: ID, guide: {} });
    const response = await getGuide(req(`/api/cves/${ID}/research`), ctx(ID));
    expect(response.status).toBe(200);
    expect((fetchMock.mock.calls[0] as unknown as [string])[0]).toBe(`http://backend.internal:8000/api/cves/${ID}/research`);
  });

  it("starts research with a same-origin POST and passes 202 through", async () => {
    const fetchMock = backend(202, { cve_id: ID, status: "queued" });
    const response = await startResearch(
      req(`/api/cves/${ID}/research`, { method: "POST", headers: sameOrigin, body: '{"refresh":true}' }),
      ctx(ID),
    );
    expect(response.status).toBe(202);
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.method).toBe("POST");
    expect(init.body).toBe('{"refresh":true}');
  });

  it("only forwards refresh when it is exactly true", async () => {
    for (const body of ['{"refresh":"yes"}', "not json", '{"refresh":1,"x":"<script>"}', ""]) {
      const fetchMock = backend(202, { cve_id: ID, status: "queued" });
      await startResearch(req(`/api/cves/${ID}/research`, { method: "POST", headers: sameOrigin, body }), ctx(ID));
      expect((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body).toBe('{"refresh":false}');
    }
  });

  it("refuses cross-site and header-less POSTs without contacting the backend", async () => {
    const fetchMock = backend(202, {});
    const attempts: Record<string, string>[] = [
      { "Sec-Fetch-Site": "cross-site", "Content-Type": "application/json" },
      { "Sec-Fetch-Site": "same-site", "Content-Type": "application/json" },
      { Origin: "https://evil.example", Host: "localhost:3000" },
      {},
    ];
    for (const headers of attempts) {
      const response = await startResearch(req(`/api/cves/${ID}/research`, { method: "POST", headers, body: "{}" }), ctx(ID));
      expect(response.status).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("accepts a matching Origin when the browser sends no Sec-Fetch-Site", async () => {
    backend(202, { cve_id: ID, status: "queued" });
    const response = await startResearch(
      req(`/api/cves/${ID}/research`, { method: "POST", headers: { Origin: "http://localhost:3000", Host: "localhost:3000" }, body: "{}" }),
      ctx(ID),
    );
    expect(response.status).toBe(202);
  });

  it.each(["nope", "CVE-1-1", "%E0%A4%A", "CVE-2099-12345%2F..%2Fadmin", "CVE-2099-12345%00"])(
    "404s malformed CVE id %j without contacting the backend",
    async (id) => {
      const fetchMock = backend(200, {});
      for (const handler of [getStatus, getGuide]) {
        const response = await handler(req(`/api/cves/x/research`), ctx(id));
        expect(response.status).toBe(404);
      }
      const post = await startResearch(req("/api/cves/x/research", { method: "POST", headers: sameOrigin, body: "{}" }), ctx(id));
      expect(post.status).toBe(404);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("forwards only a well-formed X-Forwarded-For and nothing else from the visitor", async () => {
    const fetchMock = backend(200, { cve_id: ID, status: "queued" });
    await getStatus(
      req(`/api/cves/${ID}/research/status`, { headers: { Cookie: "session=secret", Authorization: "Bearer secret", "X-Api-Key": "k" } }),
      ctx(ID),
    );
    const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(init.headers).toEqual({ Accept: "application/json", "X-Forwarded-For": "203.0.113.7" });

    forwarded = "1.2.3.4\r\nX-Injected: yes";
    await getStatus(req(`/api/cves/${ID}/research/status`), ctx(ID));
    const second = (fetchMock.mock.calls[1] as unknown as [string, RequestInit])[1];
    expect(second.headers).toEqual({ Accept: "application/json" });
  });

  it("passes rate limiting through with Retry-After and only the fixed error fields", async () => {
    backend(
      429,
      { error: { code: "rate_limited", message: "Too many.", request_id: "x", details: [{ secret: "internal" }], stack: "trace" } },
      { "Retry-After": "120", "Set-Cookie": "leak=1", "X-Internal": "yes" },
    );
    const response = await startResearch(req(`/api/cves/${ID}/research`, { method: "POST", headers: sameOrigin, body: "{}" }), ctx(ID));
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("120");
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(response.headers.get("x-internal")).toBeNull();
    expect(await response.json()).toEqual({ error: { code: "rate_limited", message: "Too many." } });
  });

  it("does not let unexpected upstream statuses or bodies through", async () => {
    for (const [status, body] of [
      [500, { error: { message: "psycopg.OperationalError: password authentication failed for user cvelearn" } }],
      [502, "<html>bad gateway from 10.0.0.4</html>"],
      [302, ""],
      [200, "not json"],
      [200, "[1,2,3]"],
    ] as const) {
      backend(status, body);
      const response = await getStatus(req(`/api/cves/${ID}/research/status`), ctx(ID));
      expect(response.status).toBe(503);
      const text = await response.text();
      expect(text).not.toMatch(/psycopg|password|10\.0\.0\.4|cvelearn/);
    }
  });

  it("reports an unreachable backend without leaking its address", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("connect ECONNREFUSED 10.0.0.9:8000"); }));
    const response = await getStatus(req(`/api/cves/${ID}/research/status`), ctx(ID));
    expect(response.status).toBe(503);
    expect(await response.text()).not.toMatch(/10\.0\.0\.9|ECONNREFUSED/);
  });
});
