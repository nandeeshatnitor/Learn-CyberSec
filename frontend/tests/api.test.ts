import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getCve, getHealth, searchCves } from "@/lib/api";
import { makeDetail, makeSearch } from "./fixtures";

const incoming = vi.hoisted(() => ({ headers: new Headers() as Headers, throws: false }));
vi.mock("next/headers", () => ({
  headers: vi.fn(async () => {
    if (incoming.throws) throw new Error("called outside a request scope");
    return incoming.headers;
  }),
}));

const fetchMock = vi.fn();

function respond(status: number, body: unknown, headers: Record<string, string> = {}) {
  fetchMock.mockResolvedValueOnce(
    new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers }),
  );
}

beforeEach(() => {
  incoming.headers = new Headers();
  incoming.throws = false;
  vi.stubGlobal("fetch", fetchMock);
  process.env.BACKEND_URL = "http://backend.internal:8000/";
});

afterEach(() => {
  fetchMock.mockReset();
  vi.unstubAllGlobals();
  delete process.env.BACKEND_URL;
});

const lastUrl = () => String(fetchMock.mock.calls.at(-1)?.[0]);
const lastInit = () => fetchMock.mock.calls.at(-1)?.[1] as RequestInit;

describe("requests", () => {
  it("calls the configured backend, uncached, with no credentials", async () => {
    respond(200, makeDetail());
    await getCve("CVE-2021-44228");
    expect(lastUrl()).toBe("http://backend.internal:8000/api/cves/CVE-2021-44228");
    expect(lastInit().cache).toBe("no-store");
    expect(lastInit().signal).toBeInstanceOf(AbortSignal);
    expect(Object.keys(lastInit().headers as object)).toEqual(["Accept"]); // nothing secret to send
  });

  describe("visitor address forwarding", () => {
    const sentHeaders = () => lastInit().headers as Record<string, string>;

    it("forwards X-Forwarded-For so the backend can limit per visitor", async () => {
      incoming.headers = new Headers({ "x-forwarded-for": "198.51.100.7, 10.0.0.2" });
      respond(200, makeDetail());
      await getCve("CVE-2021-44228");
      expect(sentHeaders()["X-Forwarded-For"]).toBe("198.51.100.7, 10.0.0.2");
    });

    it("never forwards cookies, authorization or any other incoming header", async () => {
      incoming.headers = new Headers({
        "x-forwarded-for": "198.51.100.7",
        cookie: "session=secret",
        authorization: "Bearer secret",
        "x-api-key": "secret",
        host: "example.com",
      });
      respond(200, makeSearch());
      await searchCves("apache");
      expect(Object.keys(sentHeaders()).sort()).toEqual(["Accept", "X-Forwarded-For"]);
      expect(JSON.stringify(lastInit())).not.toContain("secret");
    });

    it.each(["<script>", "1.2.3.4\r\nX-Evil: 1", "x".repeat(300), "1.2.3.4; drop"])("drops a malformed value %#", async (value) => {
      incoming.headers = new Headers();
      incoming.headers.set("x-forwarded-for", value.replace(/[\r\n]/g, " "));
      respond(200, makeDetail());
      await getCve("CVE-2021-44228");
      expect(sentHeaders()["X-Forwarded-For"]).toBeUndefined();
    });

    it("works outside a request scope", async () => {
      incoming.throws = true;
      respond(200, makeDetail());
      expect(await getCve("CVE-2021-44228")).toMatchObject({ ok: true });
      expect(sentHeaders()["X-Forwarded-For"]).toBeUndefined();
    });
  });

  it("encodes path segments and query parameters", async () => {
    respond(200, makeDetail());
    await getCve("CVE-2021-44228/../x");
    expect(lastUrl()).toContain("CVE-2021-44228%2F..%2Fx");

    respond(200, makeSearch());
    await searchCves("a&b=c #x", { page: 2, limit: 10, severity: "HIGH", knownExploited: true });
    const url = new URL(lastUrl());
    expect(url.searchParams.get("q")).toBe("a&b=c #x");
    expect([...url.searchParams.keys()].sort()).toEqual(["known_exploited", "limit", "page", "q", "severity"]);
    expect(url.searchParams.get("known_exploited")).toBe("true");
  });

  it("omits unset filters", async () => {
    respond(200, makeSearch());
    await searchCves("apache");
    expect([...new URL(lastUrl()).searchParams.keys()]).toEqual(["q"]);
  });
});

describe("results", () => {
  it("returns parsed data", async () => {
    respond(200, makeDetail());
    const result = await getCve("CVE-2021-44228");
    expect(result.ok && result.data.cve_id).toBe("CVE-2021-44228");
  });

  it.each([
    [404, "not_found"],
    [422, "invalid"],
    [500, "unavailable"],
    [502, "unavailable"],
  ])("maps HTTP %i to %s", async (status, kind) => {
    respond(status, { error: { code: "x", message: "y" } });
    const result = await getCve("CVE-2021-44228");
    expect(result).toMatchObject({ ok: false, kind });
  });

  it("reports rate limiting with the retry delay", async () => {
    respond(429, { error: { code: "rate_limited" } }, { "Retry-After": "12" });
    expect(await searchCves("x")).toMatchObject({ ok: false, kind: "rate_limited", retryAfter: 12 });
  });

  it("ignores a nonsense Retry-After", async () => {
    respond(429, {}, { "Retry-After": "soon" });
    const result = await searchCves("x");
    expect(result).toMatchObject({ ok: false, kind: "rate_limited" });
    expect(result.ok === false && result.retryAfter).toBeUndefined();
  });

  it("surfaces per-provider outcomes when nothing could be reached", async () => {
    respond(503, {
      error: {
        code: "providers_unavailable",
        message: "m",
        details: [
          { provider: "nvd", name: "NVD", status: "unavailable", message: "down" },
          { not: "a provider status" },
          "garbage",
        ],
      },
    });
    const result = await getCve("CVE-2021-44228");
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.providers).toEqual([
      { provider: "nvd", name: "NVD", status: "unavailable", message: "down" },
    ]);
  });

  it("treats a network failure, timeout or abort as unavailable, without throwing", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("fetch failed"));
    expect(await getCve("CVE-2021-44228")).toMatchObject({ ok: false, kind: "unavailable" });
    fetchMock.mockRejectedValueOnce(new DOMException("timed out", "TimeoutError"));
    expect(await searchCves("x")).toMatchObject({ ok: false, kind: "unavailable" });
  });

  it.each([
    ["not json at all", 200],
    [JSON.stringify(["array", "not", "object"]), 200],
    [JSON.stringify({ unexpected: "shape" }), 200],
  ])("rejects an unreadable or unexpected success body %#", async (body) => {
    respond(200, body);
    expect(await getCve("CVE-2021-44228")).toMatchObject({ ok: false, kind: "unavailable" });
  });

  it("does not leak backend error text into results", async () => {
    respond(500, "Traceback: secret internal detail at /srv/app.py");
    const result = await getCve("CVE-2021-44228");
    expect(JSON.stringify(result)).not.toContain("secret internal detail");
  });

  it("accepts the health endpoint's 503 body (database down) as data", async () => {
    respond(503, { status: "unhealthy", version: "1", environment: "x", checks: {} });
    expect(await getHealth()).toMatchObject({ ok: true, data: { status: "unhealthy" } });
  });
});
