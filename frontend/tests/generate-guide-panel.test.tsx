import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { GenerateGuidePanel } from "@/components/research/generate-guide-panel";

import { makeGuideResponse, makeStatus } from "./research-fixtures";

type Reply = { status?: number; body: unknown; headers?: Record<string, string> };

/** A scripted backend: one queue of replies per (method, endpoint). */
function scriptFetch(script: {
  status?: Reply[];
  start?: Reply[];
  guide?: Reply[];
}) {
  const queues = { status: [...(script.status ?? [])], start: [...(script.start ?? [])], guide: [...(script.guide ?? [])] };
  const calls: { key: string; method: string; body?: string }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const key = url.endsWith("/status") ? "status" : method === "POST" ? "start" : "guide";
    calls.push({ key, method, body: init?.body as string | undefined });
    const queue = queues[key];
    const reply = queue.length > 1 ? queue.shift()! : queue[0];
    if (!reply) throw new Error(`unscripted call: ${method} ${url}`);
    const status = reply.status ?? 200;
    // A plain object instead of a real Response: reading a real body needs event-loop turns that
    // fake timers would hold back.
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: new Headers(reply.headers),
      json: async () => reply.body,
    } as unknown as Response;
  });
  vi.stubGlobal("fetch", fn);
  return { fn, calls, count: (key: string) => calls.filter((c) => c.key === key).length };
}

async function settle() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
}
async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

const CVE = "CVE-2099-12345";
/** user-event waits on timers that vitest's fake clock would hold back, so click directly. */
async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name }));
  });
}

beforeEach(() => vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] }));
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("generate learning guide panel", () => {
  it("offers the button when nothing has been generated, and states the scope", async () => {
    scriptFetch({ status: [{ body: makeStatus("not_started") }] });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    expect(screen.getByRole("button", { name: "Generate Learning Guide" })).toBeInTheDocument();
    expect(screen.getByText(/local,\s+intentionally vulnerable or authorized lab environments/)).toBeInTheDocument();
    expect(screen.getByText(/do not say enough, the guide says so/)).toBeInTheDocument();
  });

  it("walks Queued -> Researching -> Synthesizing -> Ready and then shows the guide", async () => {
    const backend = scriptFetch({
      status: [
        { body: makeStatus("not_started") },
        { body: makeStatus("queued") },
        { body: makeStatus("researching", { stage_detail: "Retrieving 9 documents" }) },
        { body: makeStatus("synthesizing", { stage_detail: "Writing and checking the guide" }) },
        { body: makeStatus("ready") },
      ],
      start: [{ status: 202, body: makeStatus("queued") }],
      guide: [{ body: makeGuideResponse() }],
    });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();

    await click("Generate Learning Guide");
    await settle();
    const progress = screen.getByTestId("research-progress");
    expect(progress).toHaveAttribute("aria-live", "polite");
    expect(progress.querySelector("[aria-current=step]")).toHaveTextContent("Queued");
    expect(backend.calls.find((c) => c.key === "start")?.body).toBe('{"refresh":false}');

    await advance(3_000);
    expect(screen.getByTestId("research-progress").querySelector("[aria-current=step]")).toHaveTextContent("Queued");
    await advance(4_000);
    expect(screen.getByTestId("research-progress").querySelector("[aria-current=step]")).toHaveTextContent("Researching");
    expect(screen.getByTestId("research-progress")).toHaveTextContent("Retrieving 9 documents");
    await advance(5_000);
    expect(screen.getByTestId("research-progress").querySelector("[aria-current=step]")).toHaveTextContent("Synthesizing");
    await advance(7_000);

    expect(screen.getByTestId("guide-view")).toBeInTheDocument();
    expect(screen.queryByTestId("research-progress")).toBeNull();
    expect(screen.getByText("Upgrade to AcmeDocs 4.2.4 or later.")).toBeInTheDocument();
    expect(backend.count("guide")).toBe(1);
  });

  it("shows an existing guide straight away without generating", async () => {
    const backend = scriptFetch({
      status: [{ body: makeStatus("ready") }],
      guide: [{ body: makeGuideResponse() }],
    });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    expect(screen.getByTestId("guide-view")).toBeInTheDocument();
    expect(backend.count("start")).toBe(0);
    expect(screen.getByRole("button", { name: "Regenerate guide" })).toBeInTheDocument();
  });

  it("resumes following a run that is already in progress (page reload)", async () => {
    const backend = scriptFetch({
      status: [{ body: makeStatus("researching") }, { body: makeStatus("ready") }],
      guide: [{ body: makeGuideResponse() }],
    });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    expect(screen.getByTestId("research-progress")).toBeInTheDocument();
    await advance(4_000);
    expect(screen.getByTestId("guide-view")).toBeInTheDocument();
    expect(backend.count("start")).toBe(0);
  });

  it("uses a stored guide when the backend reports it already exists (cached start)", async () => {
    const backend = scriptFetch({
      status: [{ body: makeStatus("not_started") }],
      start: [{ status: 200, body: makeStatus("ready", { cached: true }) }],
      guide: [{ body: makeGuideResponse() }],
    });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    await click("Generate Learning Guide");
    await settle();
    expect(screen.getByTestId("guide-view")).toBeInTheDocument();
    expect(backend.count("status")).toBe(1);
  });

  it("reports a failed run with its safe message and lets the reader retry", async () => {
    const backend = scriptFetch({
      status: [{ body: makeStatus("not_started") }, { body: makeStatus("failed", { error: { code: "providers_unavailable", message: "Vulnerability data providers are unavailable right now." } }) }],
      start: [{ status: 202, body: makeStatus("queued") }, { status: 202, body: makeStatus("queued") }],
    });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    await click("Generate Learning Guide");
    await settle();
    await advance(4_000);
    expect(screen.getByTestId("research-error")).toHaveTextContent("Vulnerability data providers are unavailable right now.");
    await click("Try again");
    await settle();
    expect(backend.count("start")).toBe(2);
    expect(screen.getByTestId("research-progress")).toBeInTheDocument();
  });

  it("explains rate limiting", async () => {
    scriptFetch({
      status: [{ body: makeStatus("not_started") }],
      start: [{ status: 429, headers: { "Retry-After": "1800" }, body: { error: { code: "rate_limited", message: "You have started too many learning guides recently." } } }],
    });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    await click("Generate Learning Guide");
    await settle();
    expect(screen.getByTestId("research-error")).toHaveTextContent(/too many learning guides recently/);
    expect(screen.getByTestId("research-error")).toHaveTextContent(/30 minute/);
  });

  it("says when the feature is switched off and offers no button", async () => {
    scriptFetch({ status: [{ status: 503, body: { error: { code: "research_disabled", message: "off" } } }] });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    expect(screen.getByTestId("research-error")).toHaveTextContent(/unavailable|not available|turned off/i);
  });

  it("keeps the previous guide when a regeneration fails", async () => {
    scriptFetch({
      status: [{ body: makeStatus("ready") }, { body: makeStatus("failed", { guide_available: true }) }],
      start: [{ status: 202, body: makeStatus("queued", { guide_available: true }) }],
      guide: [{ body: makeGuideResponse() }],
    });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    await click("Regenerate guide");
    await settle();
    await advance(4_000);
    expect(screen.getByTestId("guide-view")).toBeInTheDocument();
  });

  it("tells the reader when regeneration is not yet allowed", async () => {
    scriptFetch({
      status: [{ body: makeStatus("ready") }],
      start: [{ status: 200, body: makeStatus("ready", { cached: true, refresh_available_at: "2026-09-30T08:00:00Z" }) }],
      guide: [{ body: makeGuideResponse() }],
    });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    await click("Regenerate guide");
    await settle();
    expect(screen.getByRole("status", { name: "" })).toHaveTextContent(/can be regenerated after 2026-09-30 08:00 UTC/);
    expect(screen.getByTestId("guide-view")).toBeInTheDocument();
  });

  it("stops polling when the page is left", async () => {
    const backend = scriptFetch({ status: [{ body: makeStatus("researching") }] });
    const { unmount } = render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    await advance(3_000);
    const before = backend.count("status");
    unmount();
    await advance(60_000);
    expect(backend.count("status")).toBe(before);
  });

  it("backs off and eventually reports a problem when the service keeps failing", async () => {
    const backend = scriptFetch({
      status: [{ body: makeStatus("researching") }, { status: 503, body: { error: { code: "unavailable", message: "The API is not available right now." } } }],
    });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    await advance(120_000);
    expect(screen.getByTestId("research-error")).toHaveTextContent(/not available/);
    expect(backend.count("status")).toBeLessThanOrEqual(7);
  });

  it("gives up after a long time instead of polling forever", async () => {
    const backend = scriptFetch({ status: [{ body: makeStatus("researching") }] });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    await advance(16 * 60_000);
    expect(screen.getByTestId("research-error")).toHaveTextContent(/taking longer than expected/);
    const calls = backend.count("status");
    await advance(5 * 60_000);
    expect(backend.count("status")).toBe(calls);
  });

  it("only ever talks to this site's own research routes", async () => {
    const backend = scriptFetch({ status: [{ body: makeStatus("not_started") }], start: [{ status: 202, body: makeStatus("queued") }] });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    await click("Generate Learning Guide");
    await settle();
    for (const [input, init] of backend.fn.mock.calls) {
      expect(String(input)).toMatch(/^\/api\/cves\/CVE-2099-12345\/research(\/status)?$/);
      expect((init as RequestInit).credentials).toBe("same-origin");
    }
  });

  it("rejects malformed responses instead of rendering them", async () => {
    scriptFetch({ status: [{ body: { nonsense: true } }] });
    render(<GenerateGuidePanel cveId={CVE} />);
    await settle();
    expect(screen.getByTestId("research-error")).toHaveTextContent(/unexpected response/);
  });
});
