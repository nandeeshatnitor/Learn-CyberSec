import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CveSearchForm } from "@/components/cve-search-form";
import { CveErrorView } from "@/components/cve/cve-error-view";
import { SearchResultList } from "@/components/cve/search-result-list";
import { SearchEmptyState, SearchErrorState, SearchPrompt } from "@/components/cve/search-states";
import { LoadingSkeleton } from "@/components/loading-skeleton";
import { Pagination } from "@/components/pagination";
import { makeBareCve, makeCve } from "./fixtures";

describe("CveSearchForm", () => {
  it("is a GET form to /cves with a bounded, labelled input", () => {
    render(<CveSearchForm />);
    const input = screen.getByLabelText(/search by cve id/i);
    expect(input).toHaveAttribute("name", "q");
    expect(input).toHaveAttribute("maxlength", "100");
    expect(input.closest("form")).toHaveAttribute("action", "/cves");
    expect(input.closest("form")).toHaveAttribute("method", "get");
    expect(screen.queryByLabelText(/severity/i)).toBeNull(); // filters only on the results page
  });

  it("offers severity and KEV filters and keeps their current values", () => {
    render(<CveSearchForm showFilters defaultValue="apache" severity="HIGH" knownExploited />);
    expect(screen.getByLabelText(/^search by/i)).toHaveValue("apache");
    expect(screen.getByLabelText("Severity")).toHaveValue("HIGH");
    expect(screen.getByLabelText(/Known exploited only/)).toBeChecked();
    const options = screen.getAllByRole("option").map((o) => o.getAttribute("value"));
    expect(options).toEqual(["", "CRITICAL", "HIGH", "MEDIUM", "LOW"]);
  });

  it("does not carry the page number, so a new search starts at page 1", () => {
    render(<CveSearchForm showFilters />);
    expect(document.querySelector("input[name=page]")).toBeNull();
  });
});

describe("SearchResultList", () => {
  it("shows the key fields of each result", () => {
    render(<SearchResultList items={[makeCve()]} />);
    const link = screen.getByRole("link");
    expect(link).toHaveAttribute("href", "/cves/CVE-2021-44228");
    expect(screen.getByText("CVE-2021-44228")).toBeInTheDocument();
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText("Known exploited (KEV)")).toBeInTheDocument();
    expect(screen.getByText("Published 2021-12-10")).toBeInTheDocument();
    expect(screen.getByText(/Apache Log4j2 JNDI features/)).toBeInTheDocument();
    expect(screen.getByText(/apache log4j, Apache Software Foundation Apache Log4j2/)).toBeInTheDocument();
    expect(screen.getByText("Source: NVD")).toBeInTheDocument();
  });

  it("summarises long product lists", () => {
    const base = makeCve().affected_products[0]!;
    const many = ["a", "b", "c", "d", "e"].map((p) => ({ ...base, product: p, vendor: null }));
    render(<SearchResultList items={[makeCve({ affected_products: many })]} />);
    expect(screen.getByText(/a, b, c \+2 more/)).toBeInTheDocument();
  });

  it("does not claim 'not exploited' when KEV status is unknown", () => {
    render(<SearchResultList items={[makeBareCve({ cve_id: "CVE-2020-0001" })]} />);
    expect(screen.getByText("KEV status unknown")).toBeInTheDocument();
    expect(screen.getByText(/No description was available/)).toBeInTheDocument();
    expect(screen.queryByText("Known exploited (KEV)")).toBeNull();
  });

  it("shows no KEV badge for a CVE that was checked and is not listed", () => {
    render(<SearchResultList items={[makeCve({ known_exploited: false, kev: null })]} />);
    expect(screen.queryByText("Known exploited (KEV)")).toBeNull();
    expect(screen.queryByText("KEV status unknown")).toBeNull();
  });

  it("renders descriptions as text", () => {
    const { container } = render(<SearchResultList items={[makeCve({ description: "<img src=x onerror=alert(1)>" })]} />);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  });
});

describe("Pagination", () => {
  const hrefFor = (page: number) => `/cves?q=apache&page=${page}`;

  it("renders nothing for a single page", () => {
    const { container } = render(<Pagination page={1} pages={1} hrefFor={hrefFor} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("links only in the directions that exist", () => {
    const { rerender } = render(<Pagination page={1} pages={3} hrefFor={hrefFor} />);
    expect(screen.getByText("Page 1 of 3")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Next/ })).toHaveAttribute("href", "/cves?q=apache&page=2");
    expect(screen.queryByRole("link", { name: /Previous/ })).toBeNull();

    rerender(<Pagination page={3} pages={3} hrefFor={hrefFor} />);
    expect(screen.getByRole("link", { name: /Previous/ })).toHaveAttribute("href", "/cves?q=apache&page=2");
    expect(screen.queryByRole("link", { name: /Next/ })).toBeNull();

    rerender(<Pagination page={2} pages={3} hrefFor={hrefFor} />);
    expect(screen.getAllByRole("link")).toHaveLength(2);
  });
});

describe("search states", () => {
  it("prompt explains the supported query types", () => {
    render(<SearchPrompt />);
    expect(screen.getByText(/product or vendor name/)).toBeInTheDocument();
  });

  it("empty state names the query and hints at filters", () => {
    const { rerender } = render(<SearchEmptyState query="zzz" filtered={false} />);
    expect(screen.getByTestId("empty-state")).toHaveTextContent("No CVEs matched zzz.");
    rerender(<SearchEmptyState query="zzz" filtered />);
    expect(screen.getByTestId("empty-state")).toHaveTextContent(/removing a filter/);
  });

  it("empty state shows the query as text", () => {
    const { container } = render(<SearchEmptyState query="<script>alert(1)</script>" filtered={false} />);
    expect(container.querySelector("script")).toBeNull();
  });

  it.each([
    ["unavailable", /unavailable right now/],
    ["rate_limited", /too quickly/],
    ["invalid", /could not be processed/],
  ] as const)("error state for %s", (kind, pattern) => {
    render(<SearchErrorState error={{ ok: false, kind, message: "internal detail" }} />);
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(pattern);
    expect(alert).not.toHaveTextContent("internal detail");
  });

  it("rate-limit error shows the retry delay", () => {
    render(<SearchErrorState error={{ ok: false, kind: "rate_limited", message: "x", retryAfter: 12.2 }} />);
    expect(screen.getByRole("alert")).toHaveTextContent("about 13 seconds");
  });
});

describe("CveErrorView", () => {
  it("not found explains what was checked", () => {
    render(<CveErrorView cveId="CVE-1999-0001" error={{ ok: false, kind: "not_found", message: "" }} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/CVE-1999-0001 was not found/);
  });

  it("unavailable lists what each provider reported", () => {
    render(
      <CveErrorView
        cveId="CVE-2021-44228"
        error={{
          ok: false, kind: "unavailable", message: "",
          providers: [{ provider: "nvd", name: "NVD", status: "unavailable", retrieved_at: null, from_cache: false, message: "The provider is unavailable." }],
        }}
      />,
    );
    expect(screen.getByText(/Nothing is shown rather than guessing/)).toBeInTheDocument();
    expect(screen.getByText(/NVD: The provider is unavailable\./)).toBeInTheDocument();
  });
});

describe("LoadingSkeleton", () => {
  it("is announced to assistive technology", () => {
    render(<LoadingSkeleton label="Searching…" />);
    const status = screen.getByRole("status");
    expect(status).toHaveAttribute("aria-busy", "true");
    expect(status).toHaveTextContent("Searching…");
  });
});
