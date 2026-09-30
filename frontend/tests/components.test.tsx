import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CveSearchForm } from "@/components/cve-search-form";
import { DataOriginBanner } from "@/components/data-origin-banner";
import { SafeLink } from "@/components/safe-link";
import { SectionCard, UnavailableNotice } from "@/components/section-card";

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

describe("SectionCard", () => {
  it("marks unavailable sections distinctly", () => {
    const { container } = render(
      <SectionCard id="hints" title="Hints" availability="unavailable">
        <UnavailableNotice>Not available yet.</UnavailableNotice>
      </SectionCard>,
    );
    expect(screen.getByText("Not available")).toBeInTheDocument();
    expect(container.querySelector("[data-availability='unavailable']")).not.toBeNull();
  });
});

describe("CveSearchForm", () => {
  it("is a GET form to /cves with a bounded, labelled input", () => {
    render(<CveSearchForm />);
    const input = screen.getByLabelText(/search by cve id/i);
    expect(input).toHaveAttribute("name", "q");
    expect(input).toHaveAttribute("maxlength", "100");
    expect(input.closest("form")).toHaveAttribute("action", "/cves");
    expect(input.closest("form")).toHaveAttribute("method", "get");
  });
});

describe("DataOriginBanner", () => {
  it("warns for seed data", () => {
    render(<DataOriginBanner origin="seed" />);
    expect(screen.getByRole("note")).toHaveTextContent(/not.*retrieved/i);
  });

  it("is silent for retrieved data", () => {
    const { container } = render(<DataOriginBanner origin="nvd" />);
    expect(container).toBeEmptyDOMElement();
  });
});
