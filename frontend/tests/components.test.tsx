import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AffectedSoftwareSection, AffectedVersionsSection } from "@/components/cve/affected-section";
import { CvssSection } from "@/components/cve/cvss-section";
import { KevSection } from "@/components/cve/kev-section";
import { ProviderStatusBanner } from "@/components/cve/provider-status-banner";
import { ReferencesSection } from "@/components/cve/references-section";
import { SourceBadges } from "@/components/cve/source-badges";
import { SourcesSection } from "@/components/cve/sources-section";
import { WeaknessSection } from "@/components/cve/weakness-section";
import { DataOriginBanner } from "@/components/data-origin-banner";
import { SafeLink } from "@/components/safe-link";
import { SectionCard, UnavailableNotice } from "@/components/section-card";
import { makeBareCve, makeCve, okMeta } from "./fixtures";

describe("SafeLink", () => {
  it("renders a hardened link for https URLs", () => {
    render(<SafeLink href="https://nvd.nist.gov/">NVD</SafeLink>);
    const link = screen.getByRole("link", { name: /NVD/ });
    expect(link).toHaveAttribute("href", "https://nvd.nist.gov/");
    expect(link).toHaveAttribute("rel", "noopener noreferrer nofollow");
    expect(link).toHaveAttribute("target", "_blank");
  });

  it("renders inert text for dangerous URLs", () => {
    render(<SafeLink href="javascript:alert(1)">click me</SafeLink>);
    expect(screen.queryByRole("link")).toBeNull();
    expect(screen.getByText("click me")).toBeInTheDocument();
  });
});

describe("SourceBadges", () => {
  it("says where data came from, one badge per provider", () => {
    render(<SourceBadges sources={["nvd", "cisa_kev"]} />);
    expect(screen.getByText("Source: NVD")).toBeInTheDocument();
    expect(screen.getByText("Source: CISA KEV")).toBeInTheDocument();
  });

  it("renders nothing without sources", () => {
    const { container } = render(<SourceBadges sources={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("never says 'verified'", () => {
    const { container } = render(<SourceBadges sources={["nvd", "mitre", "cisa_kev"]} />);
    expect(container.textContent?.toLowerCase()).not.toContain("verified");
  });
});

describe("SectionCard", () => {
  it("shows the source of an available section", () => {
    render(
      <SectionCard id="overview" title="Overview" sources={["nvd"]}>
        body
      </SectionCard>,
    );
    expect(screen.getByText("Source: NVD")).toBeInTheDocument();
  });

  it("marks unavailable sections distinctly and shows no source", () => {
    const { container } = render(
      <SectionCard id="hints" title="Hints" unavailable sources={["nvd"]}>
        <UnavailableNotice>Not available yet.</UnavailableNotice>
      </SectionCard>,
    );
    expect(screen.getByText("Not available")).toBeInTheDocument();
    expect(screen.queryByText("Source: NVD")).toBeNull();
    expect(container.querySelector("[data-availability='unavailable']")).not.toBeNull();
  });
});

describe("DataOriginBanner", () => {
  it("warns for seed data and is silent for retrieved data", () => {
    const { rerender, container } = render(<DataOriginBanner origin="seed" />);
    expect(screen.getByRole("note")).toHaveTextContent(/not.*retrieved/i);
    rerender(<DataOriginBanner origin="providers" />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("ProviderStatusBanner", () => {
  it("is silent when everything worked", () => {
    const { container } = render(<ProviderStatusBanner meta={okMeta} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("explains an unavailable provider and shows the backend's warnings", () => {
    render(
      <ProviderStatusBanner
        meta={{
          ...okMeta,
          warnings: ["NVD: The provider is unavailable."],
          providers: [{ provider: "nvd", name: "NVD", status: "unavailable", retrieved_at: null, from_cache: false, message: "The provider is unavailable." }],
        }}
      />,
    );
    expect(screen.getByRole("status")).toHaveTextContent(/may be incomplete or out of date/);
    expect(screen.getAllByText(/NVD/).length).toBeGreaterThan(0);
  });

  it("says when a stale copy is shown and when it was retrieved", () => {
    render(
      <ProviderStatusBanner
        meta={{
          ...okMeta,
          providers: [{ provider: "nvd", name: "NVD", status: "stale", retrieved_at: "2026-09-29T08:30:00Z", from_cache: true, message: null }],
        }}
      />,
    );
    expect(screen.getByText(/showing a copy retrieved 2026-09-29 08:30 UTC/)).toBeInTheDocument();
  });

  it("appears for fallback and database-served results even without failed providers", () => {
    render(<ProviderStatusBanner meta={{ ...okMeta, served_from: "database", warnings: ["From a stored copy"] }} />);
    expect(screen.getByText("From a stored copy")).toBeInTheDocument();
  });
});

describe("CvssSection", () => {
  it("lists every metric with who reported it and marks exactly one headline", () => {
    render(<CvssSection cve={makeCve()} />);
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    expect(screen.getAllByTestId("headline-badge")).toHaveLength(1);
    expect(within(rows[0]!).getByText("NVD analysis")).toBeInTheDocument();
    expect(within(rows[0]!).getByText("Headline")).toBeInTheDocument();
    expect(screen.getByText("CNA: apache")).toBeInTheDocument();
    expect(screen.getByText("CVSS 2.0")).toBeInTheDocument();
    // NVD and the CNA reported the same vector: both rows show it
    expect(screen.getAllByText("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", { selector: "td" })).toHaveLength(2);
  });

  it("is honestly unavailable without scores", () => {
    render(<CvssSection cve={makeBareCve()} />);
    expect(screen.getByText("Not available")).toBeInTheDocument();
    expect(screen.getByText(/No CVSS score was reported/)).toBeInTheDocument();
  });
});

describe("Affected software and versions", () => {
  it("keeps each source's statement separate", () => {
    render(<AffectedSoftwareSection cve={makeCve()} />);
    expect(screen.getByText("Reported by NVD")).toBeInTheDocument();
    expect(screen.getByText("Reported by MITRE / CVE Program")).toBeInTheDocument();
    expect(screen.getByText("apache log4j")).toBeInTheDocument();
    expect(screen.getByText("Apache Software Foundation Apache Log4j2")).toBeInTheDocument();
  });

  it("formats version ranges readably", () => {
    render(<AffectedVersionsSection cve={makeCve()} />);
    expect(screen.getByText("2.0.1 ≤ version < 2.3.1")).toBeInTheDocument();
    expect(screen.getByText("2.0 beta9")).toBeInTheDocument();
    expect(screen.getByText("2.15.0 (not affected)")).toBeInTheDocument();
  });

  it("is unavailable when nothing was reported", () => {
    render(
      <>
        <AffectedSoftwareSection cve={makeBareCve()} />
        <AffectedVersionsSection cve={makeBareCve()} />
      </>,
    );
    expect(screen.getAllByText("Not available")).toHaveLength(2);
  });
});

describe("WeaknessSection", () => {
  it("links real CWEs to MITRE and explains NVD placeholders", () => {
    render(<WeaknessSection cve={makeCve()} />);
    expect(screen.getByRole("link", { name: /CWE-502/ })).toHaveAttribute(
      "href",
      "https://cwe.mitre.org/data/definitions/502.html",
    );
    expect(screen.getByText("Deserialization of Untrusted Data")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /NVD-CWE-Other/ })).toBeNull();
    expect(screen.getByText(/not in the standard CWE list/)).toBeInTheDocument();
  });
});

describe("KevSection (known exploitation status)", () => {
  it("listed: shows the catalogue details and their source", () => {
    render(<KevSection cve={makeCve()} />);
    expect(screen.getByText("Listed in the CISA KEV catalogue")).toBeInTheDocument();
    expect(screen.getByText("Source: CISA KEV")).toBeInTheDocument();
    expect(screen.getByText("2021-12-10")).toBeInTheDocument();
    expect(screen.getByText("Known")).toBeInTheDocument();
    expect(screen.getByText("Apply updates per vendor instructions.")).toBeInTheDocument();
  });

  it("listed via NVD's copy: says so", () => {
    const cve = makeCve({
      kev: { ...makeCve().kev!, source: "nvd" },
      field_sources: { known_exploited: ["nvd"] },
    });
    render(<KevSection cve={cve} />);
    expect(screen.getByText(/Reported by NVD \(its copy of CISA/)).toBeInTheDocument();
    expect(screen.getByText("Source: NVD")).toBeInTheDocument();
  });

  it("not listed: says so without claiming the CVE is safe", () => {
    render(<KevSection cve={makeCve({ known_exploited: false, kev: null, field_sources: { known_exploited: ["cisa_kev"] } })} />);
    expect(screen.getByText("Not in the CISA KEV catalogue")).toBeInTheDocument();
    expect(screen.getByText(/does not mean the vulnerability is not being exploited/)).toBeInTheDocument();
    expect(screen.getByText("Source: CISA KEV")).toBeInTheDocument();
  });

  it("unknown: never presented as 'no'", () => {
    render(<KevSection cve={makeBareCve()} />);
    expect(screen.getByText("Unknown.")).toBeInTheDocument();
    expect(screen.getByText(/could not be consulted/)).toBeInTheDocument();
    expect(screen.getByText("Not available")).toBeInTheDocument();
    expect(screen.queryByText("Not in the CISA KEV catalogue")).toBeNull();
  });

  it("renders KEV free text as text, not markup", () => {
    const cve = makeCve({ kev: { ...makeCve().kev!, notes: "<img src=x onerror=alert(1)>", short_description: "<b>bold</b>" } });
    const { container } = render(<KevSection cve={cve} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  });
});

describe("ReferencesSection", () => {
  it("preserves URLs, shows the host, who listed it, and the tags", () => {
    render(<ReferencesSection cve={makeCve()} />);
    const link = screen.getByRole("link", { name: /Apache Log4j security page/ });
    expect(link).toHaveAttribute("href", "https://logging.apache.org/log4j/2.x/security.html");
    expect(screen.getByText("logging.apache.org")).toBeInTheDocument();
    expect(screen.getByText("Listed by NVD, MITRE / CVE Program")).toBeInTheDocument();
    expect(screen.getByText("Vendor Advisory")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /openwall/ })).toHaveAttribute(
      "href",
      "http://www.openwall.com/lists/oss-security/2021/12/10/1", // http kept as published
    );
  });

  it("warns that links were not visited", () => {
    render(<ReferencesSection cve={makeCve()} />);
    expect(screen.getByText(/not been visited or checked/)).toBeInTheDocument();
  });

  it("never renders a dangerous URL as a link, even if one slipped through", () => {
    const cve = makeCve({
      references: [
        { url: "javascript:alert(document.cookie)", title: "click me", tags: [], sources: ["nvd"] },
        { url: "data:text/html,<script>alert(1)</script>", title: null, tags: [], sources: ["nvd"] },
      ],
    });
    render(<ReferencesSection cve={cve} />);
    expect(screen.queryByRole("link")).toBeNull();
    expect(screen.getByText("click me")).toBeInTheDocument();
  });

  it("renders titles and tags as text", () => {
    const cve = makeCve({
      references: [{ url: "https://ok.example/x", title: "<script>alert(1)</script>", tags: ["<b>x</b>"], sources: ["nvd"] }],
    });
    const { container } = render(<ReferencesSection cve={cve} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
  });
});

describe("SourcesSection (transparency)", () => {
  it("states that data is retrieved, not verified", () => {
    render(<SourcesSection cve={makeCve()} />);
    expect(screen.getByText(/does/, { selector: "p" })).toHaveTextContent(/retrieves and displays/);
    expect(screen.getByText(/does/, { selector: "p" })).toHaveTextContent(/not\s+independently verify/);
  });

  it("lists each source with retrieval time and a link to the original", () => {
    render(<SourcesSection cve={makeCve()} />);
    expect(screen.getByText("NVD")).toBeInTheDocument();
    expect(screen.getAllByText("Retrieved 2026-09-30 06:00 UTC")).toHaveLength(2);
    expect(screen.getByRole("link", { name: /View original at NVD/ })).toHaveAttribute(
      "href",
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    );
  });

  it("labels stale sources as older copies", () => {
    const cve = makeCve();
    cve.sources = [{ ...cve.sources[0]!, stale: true }];
    render(<SourcesSection cve={cve} />);
    expect(screen.getByText("Older copy")).toBeInTheDocument();
    expect(screen.getByText("Last retrieved 2026-09-30 06:00 UTC")).toBeInTheDocument();
  });

  it("handles a record no source retrieved (sample data)", () => {
    render(<SourcesSection cve={makeBareCve({ data_origin: "seed" })} />);
    expect(screen.getByText("No source retrieved this record.")).toBeInTheDocument();
  });
});
