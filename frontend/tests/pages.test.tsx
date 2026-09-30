import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { makeBareCve, makeCve, makeDetail, makeSearch, okMeta } from "./fixtures";

vi.mock("@/lib/api", () => ({ getCve: vi.fn(), searchCves: vi.fn(), getHealth: vi.fn() }));
vi.mock("next/navigation", () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`NEXT_REDIRECT:${url}`);
  }),
  notFound: vi.fn(() => {
    throw new Error("NEXT_NOT_FOUND");
  }),
}));

import CvePage from "@/app/cves/[cveId]/page";
import SearchPage from "@/app/cves/page";
import { getCve, searchCves } from "@/lib/api";

const getCveMock = vi.mocked(getCve);
const fetchMock = vi.fn();
const searchMock = vi.mocked(searchCves);

async function renderSearch(params: Record<string, string | string[] | undefined>) {
  render(await SearchPage({ searchParams: Promise.resolve(params) }));
}

async function renderCve(cveId: string) {
  render(await CvePage({ params: Promise.resolve({ cveId }) }));
}

beforeEach(() => {
  vi.clearAllMocks();
  // The learning-guide panel asks this site's own API for its status when it mounts.
  fetchMock.mockResolvedValue({
    ok: true,
    status: 200,
    headers: new Headers(),
    json: async () => ({ cve_id: "CVE-2021-44228", status: "not_started", stage: "No learning guide has been generated yet" }),
  });
  vi.stubGlobal("fetch", fetchMock);
});

describe("search page", () => {
  it("prompts when there is no query and does not call the API", async () => {
    await renderSearch({});
    expect(screen.getByText(/or a product or vendor name/)).toBeInTheDocument();
    expect(searchMock).not.toHaveBeenCalled();
  });

  it("redirects an exact CVE ID straight to its page", async () => {
    await expect(renderSearch({ q: "cve-2021-44228" })).rejects.toThrow("NEXT_REDIRECT:/cves/CVE-2021-44228");
    expect(searchMock).not.toHaveBeenCalled();
  });

  it("does not redirect an exact ID when filters are active", async () => {
    searchMock.mockResolvedValue({ ok: true, data: makeSearch({ query: "CVE-2021-44228", query_type: "cve_id", total: 0, items: [], pages: 0 }) });
    await renderSearch({ q: "CVE-2021-44228", severity: "LOW" });
    expect(screen.getByTestId("empty-state")).toBeInTheDocument();
  });

  it("shows results, the total, filters, sources, and pagination", async () => {
    searchMock.mockResolvedValue({ ok: true, data: makeSearch() });
    await renderSearch({ q: "log4j" });
    expect(searchMock).toHaveBeenCalledWith("log4j", { page: 1, severity: undefined, knownExploited: false });
    expect(screen.getByText("37 results for")).toBeInTheDocument();
    expect(screen.getByText("CVE-2021-44228")).toBeInTheDocument();
    expect(screen.getByText("Source: NVD")).toBeInTheDocument();
    expect(screen.getByLabelText("Severity")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Next/ })).toHaveAttribute("href", "/cves?q=log4j&page=2");
  });

  it("passes validated page and filters to the API and keeps them in pagination links", async () => {
    searchMock.mockResolvedValue({ ok: true, data: makeSearch({ page: 2, pages: 3 }) });
    await renderSearch({ q: "apache", page: "2", severity: "high", known_exploited: "true" });
    expect(searchMock).toHaveBeenCalledWith("apache", { page: 2, severity: "HIGH", knownExploited: true });
    expect(screen.getByRole("link", { name: /Next/ })).toHaveAttribute("href", "/cves?q=apache&page=3&severity=HIGH&known_exploited=true");
    expect(screen.getByRole("link", { name: /Previous/ })).toHaveAttribute("href", "/cves?q=apache&severity=HIGH&known_exploited=true");
    expect(screen.getByText(/\(filtered\)/)).toBeInTheDocument();
  });

  it("ignores hostile parameters", async () => {
    searchMock.mockResolvedValue({ ok: true, data: makeSearch() });
    await renderSearch({ q: "apache", page: "-5", severity: "<script>", known_exploited: "yes" });
    expect(searchMock).toHaveBeenCalledWith("apache", { page: 1, severity: undefined, knownExploited: false });
  });

  it("shows the empty state", async () => {
    searchMock.mockResolvedValue({ ok: true, data: makeSearch({ items: [], total: 0, pages: 0, query: "zzzz" }) });
    await renderSearch({ q: "zzzz" });
    expect(screen.getByTestId("empty-state")).toHaveTextContent("No CVEs matched zzzz");
    expect(screen.getByText("0 results for")).toBeInTheDocument();
  });

  it("shows the error state when the API is unreachable", async () => {
    searchMock.mockResolvedValue({ ok: false, kind: "unavailable", message: "x" });
    await renderSearch({ q: "apache" });
    expect(screen.getByTestId("error-state")).toHaveTextContent(/unavailable right now/);
    expect(screen.queryByTestId("results")).toBeNull();
  });

  it("explains when results come from a fallback because NVD is down", async () => {
    const meta = {
      providers: [{ provider: "nvd", name: "NVD", status: "unavailable" as const, retrieved_at: null, from_cache: false, message: "The provider is unavailable." }],
      warnings: ["NVD could not be reached. Results are limited to the CISA KEV catalogue and CVEs this platform retrieved earlier, and may be incomplete."],
      served_from: "fallback" as const,
    };
    searchMock.mockResolvedValue({ ok: true, data: makeSearch({ meta }) });
    await renderSearch({ q: "apache" });
    expect(screen.getByTestId("provider-status")).toHaveTextContent(/may be incomplete/);
    expect(screen.getByText("CVE-2021-44228")).toBeInTheDocument(); // still useful
  });

  it("notes the limits of partial-ID search", async () => {
    searchMock.mockResolvedValue({ ok: true, data: makeSearch({ query: "CVE-2021-4", query_type: "partial_cve_id", pages: 1, total: 1 }) });
    await renderSearch({ q: "CVE-2021-4" });
    expect(screen.getByText(/only match CVEs this platform has already retrieved/)).toBeInTheDocument();
  });

  it("shows the query as text", async () => {
    searchMock.mockResolvedValue({ ok: true, data: makeSearch({ query: "<img src=x onerror=alert(1)>", items: [], total: 0, pages: 0 }) });
    const { container } = render(await SearchPage({ searchParams: Promise.resolve({ q: "<img src=x onerror=alert(1)>" }) }));
    expect(container.querySelector("img")).toBeNull();
  });
});

describe("CVE page", () => {
  it("renders every required section with visible attribution", async () => {
    getCveMock.mockResolvedValue({ ok: true, data: makeDetail() });
    await renderCve("CVE-2021-44228");

    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("CVE-2021-44228");
    for (const title of [
      "Overview", "Severity", "CVSS", "Affected software", "Affected versions", "Weakness (CWE)",
      "Known exploitation status", "References", "Sources and retrieval",
    ]) {
      const section = screen.getByRole("heading", { name: title }).closest("section")!;
      expect(section).toHaveAttribute("data-availability", "available");
      expect(section.querySelector("[data-testid=source-badges], h3, p")).not.toBeNull();
    }
    expect(screen.getAllByText("Source: NVD").length).toBeGreaterThan(3);
    expect(screen.getAllByText("Source: CISA KEV").length).toBeGreaterThan(0);
  });

  it("says the information is retrieved, not verified", async () => {
    getCveMock.mockResolvedValue({ ok: true, data: makeDetail() });
    await renderCve("CVE-2021-44228");
    expect(screen.getByText(/has not\s+been independently verified/)).toBeInTheDocument();
  });

  it("keeps the later-phase sections clearly unavailable", async () => {
    getCveMock.mockResolvedValue({ ok: true, data: makeDetail() });
    await renderCve("CVE-2021-44228");
    expect(screen.getByRole("heading", { name: "Hints" }).closest("section")).toHaveAttribute("data-availability", "unavailable");
  });

  it("offers to generate a learning guide instead of a placeholder", async () => {
    getCveMock.mockResolvedValue({ ok: true, data: makeDetail() });
    await renderCve("CVE-2021-44228");
    expect(screen.getByRole("heading", { name: "Learning guide" }).closest("section")).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Generate Learning Guide" })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/cves/CVE-2021-44228/research/status", expect.anything());
  });

  it("normalises the ID from the URL", async () => {
    getCveMock.mockResolvedValue({ ok: true, data: makeDetail() });
    await renderCve("cve-2021-44228");
    expect(getCveMock).toHaveBeenCalledWith("CVE-2021-44228");
  });

  it.each(["nope", "%E0%A4%A", "CVE-2021-44228%00", "CVE-2021-1"])("404s malformed id %j without calling the API", async (id) => {
    await expect(renderCve(id)).rejects.toThrow("NEXT_NOT_FOUND");
    expect(getCveMock).not.toHaveBeenCalled();
  });

  it("degrades per section when the sources gave little", async () => {
    getCveMock.mockResolvedValue({ ok: true, data: { ...makeBareCve({ cve_id: "CVE-2020-0001", known_exploited: null }), meta: okMeta } });
    await renderCve("CVE-2020-0001");
    for (const title of ["Overview", "Severity", "CVSS", "Affected software", "Affected versions", "Weakness (CWE)", "Known exploitation status", "References"]) {
      expect(screen.getByRole("heading", { name: title }).closest("section")).toHaveAttribute("data-availability", "unavailable");
    }
    expect(screen.getByText("No source retrieved this record.")).toBeInTheDocument();
  });

  it("flags stale data and unavailable providers at the top", async () => {
    const meta = {
      providers: [
        { provider: "nvd", name: "NVD", status: "stale" as const, retrieved_at: "2026-09-29T08:30:00Z", from_cache: true, message: null },
        { provider: "mitre", name: "MITRE / CVE Program", status: "unavailable" as const, retrieved_at: null, from_cache: false, message: "The provider is unavailable." },
      ],
      warnings: ["MITRE / CVE Program: The provider is unavailable."],
      served_from: "providers" as const,
    };
    getCveMock.mockResolvedValue({ ok: true, data: makeDetail({}, meta) });
    await renderCve("CVE-2021-44228");
    expect(screen.getByTestId("provider-status")).toHaveTextContent(/showing a copy retrieved 2026-09-29 08:30 UTC/);
    expect(screen.getByTestId("provider-status")).toHaveTextContent(/incomplete or out of date/);
  });

  it("warns on sample data", async () => {
    getCveMock.mockResolvedValue({ ok: true, data: makeDetail({ data_origin: "seed", sources: [] }) });
    await renderCve("CVE-2021-44228");
    expect(screen.getByRole("note")).toHaveTextContent(/Development sample record/);
  });

  it.each([
    [{ ok: false, kind: "not_found", message: "" }, /was not found/],
    [{ ok: false, kind: "unavailable", message: "" }, /data sources are unavailable/],
    [{ ok: false, kind: "rate_limited", message: "" }, /Too many requests/],
  ] as const)("shows a useful error page for %j", async (error, pattern) => {
    getCveMock.mockResolvedValue(error);
    await renderCve("CVE-2021-44228");
    expect(screen.getByRole("alert")).toHaveTextContent(pattern);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("CVE-2021-44228");
  });

  it("renders hostile description text inertly", async () => {
    getCveMock.mockResolvedValue({ ok: true, data: makeDetail({ description: "<script>alert(1)</script><img src=x onerror=alert(1)>" }) });
    const { container } = render(await CvePage({ params: Promise.resolve({ cveId: "CVE-2021-44228" }) }));
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(/<script>alert\(1\)<\/script>/)).toBeInTheDocument();
  });

  it("renders a record whose only data is exploitation status", async () => {
    getCveMock.mockResolvedValue({ ok: true, data: makeDetail({ description: null, cvss: null, cvss_metrics: [], severity: null, cwes: [], references: [], affected_products: [] }) });
    await renderCve("CVE-2021-44228");
    expect(screen.getByRole("heading", { name: "Overview" }).closest("section")).toHaveAttribute("data-availability", "unavailable");
    expect(screen.getByText("Listed in the CISA KEV catalogue")).toBeInTheDocument();
  });
});

it("a search result and the detail page agree on the ID they link to", async () => {
  searchMock.mockResolvedValue({ ok: true, data: makeSearch({ items: [makeCve({ cve_id: "CVE-2021-45105" })] }) });
  await renderSearch({ q: "log4j" });
  expect(screen.getByRole("link", { name: /CVE-2021-45105/ })).toHaveAttribute("href", "/cves/CVE-2021-45105");
});
