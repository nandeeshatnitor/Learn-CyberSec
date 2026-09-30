import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GuideView } from "@/components/research/guide-view";

import { claim, makeGuide, makeGuideResponse } from "./research-fixtures";

const view = (overrides = {}) => render(<GuideView response={makeGuideResponse(makeGuide(overrides))} />);

describe("guide view", () => {
  it("shows every section of the guide, in order, with the safety notice first", () => {
    view();
    expect(screen.getByRole("note")).toHaveTextContent(/education and authorized testing only/i);
    for (const title of [
      "Research sources", "Confidence", "Learning guide", "Reproduction", "Technical explanation",
      "Remediation", "References used by this guide",
    ]) {
      expect(screen.getByRole("heading", { name: title })).toBeInTheDocument();
    }
    const numbered = screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent ?? "");
    for (const [index, text] of [
      "What is the vulnerability?", "Why does it happen?", "Affected versions", "Prerequisites",
      "Safe, local reproduction environment", "Reproduction procedure", "What to observe",
      "Why the reproduction works", "Impact", "How to fix or mitigate it", "Sources",
    ].entries()) {
      expect(numbered.some((h) => h.includes(`${index + 1}.`) && h.includes(text))).toBe(true);
    }
  });

  it("puts citations next to claims and links them to the reference list", () => {
    view();
    const claimRow = screen.getByText("The renderer evaluates the header without sanitizing it.").closest("li")!;
    const chip = within(claimRow).getByRole("link", { name: /Source S3/ });
    expect(chip).toHaveAttribute("href", "#guide-source-S3");
    expect(document.getElementById("guide-source-S3")).toBeInTheDocument();
    expect(within(claimRow).getByText("Documented")).toBeInTheDocument();
  });

  it("labels each level of evidence", () => {
    view();
    expect(screen.getAllByText("Multiple sources").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Synthesized").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Uncertain").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Documented").length).toBeGreaterThan(0);
  });

  it("lets a reader open the exact excerpt a claim rests on", () => {
    view();
    const claimRow = screen.getByText("The renderer evaluates the header without sanitizing it.").closest("li")!;
    const details = within(claimRow).getByText(/Show evidence/).closest("details")!;
    expect(details).toHaveTextContent("Upgrade to AcmeDocs 4.2.4 or later. As a workaround");
    expect(details).toHaveTextContent("[S3]");
  });

  it("shows confidence, how it was computed, and the gaps", () => {
    view();
    expect(screen.getByTestId("confidence-level")).toHaveTextContent("Overall: Medium");
    expect(screen.getByTestId("reproduction-confidence")).toHaveTextContent("Reproduction: Medium");
    expect(screen.getByText(/not the model's own opinion/)).toBeInTheDocument();
    expect(screen.getByTestId("limitations")).toHaveTextContent("Only one document describes the reproduction.");
  });

  it("lists sources used and why the others were not", () => {
    view();
    expect(screen.getByTestId("sources-summary")).toHaveTextContent("11 public sources found, 2 retrieved documents used");
    expect(within(screen.getByTestId("used-sources")).getAllByRole("listitem")).toHaveLength(2);
    const unused = screen.getByTestId("unused-sources");
    expect(unused).toHaveTextContent(/robots.txt does not allow automated access/);
    expect(unused).toHaveTextContent(/hidden text addressed to AI assistants/);
  });

  it("shows commands as inert text with a reminder that nothing is run", () => {
    view();
    const code = screen.getByText("docker run --rm -p 127.0.0.1:8080:8080 acmedocs/vulnerable:4.2.3");
    expect(code.tagName).toBe("CODE");
    expect(screen.getByText(/Nothing on this site runs it/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /run|execute|copy/i })).toBeNull();
  });

  it("explains a withheld command instead of showing it", () => {
    const guide = makeGuide();
    guide.reproduction.steps = [
      { ...guide.reproduction.steps[0]!, command: null, command_withheld: "pipes_download_to_interpreter" },
    ];
    render(<GuideView response={makeGuideResponse(guide)} />);
    expect(screen.getByText(/Command withheld/)).toHaveTextContent(/downloads and runs code in one step/);
    expect(document.querySelector("pre")).toBeNull();
  });

  it("says so plainly when no reproduction could be established", () => {
    const guide = makeGuide();
    guide.reproduction = {
      status: "not_established",
      statement: "A reproduction procedure could not be established from the public sources retrieved.",
      environment: [], steps: [], expected_observation: [], evidence: [],
    };
    render(<GuideView response={makeGuideResponse(guide)} />);
    const status = screen.getByTestId("reproduction-status");
    expect(status).toHaveAttribute("data-status", "not_established");
    expect(status).toHaveTextContent(/Reproduction not established/);
    expect(status).toHaveTextContent(/could not be established/);
    expect(screen.queryByTestId("repro-step")).toBeNull();
    expect(screen.queryByText("Reproduction procedure")).toBeNull();
    expect(screen.getByRole("heading", { name: "Reproduction" }).closest("section")).toHaveAttribute("data-availability", "unavailable");
  });

  it("renders partial reproduction with its stated caveats", () => {
    const guide = makeGuide();
    guide.reproduction.status = "partial";
    guide.reproduction.statement = "Only partially established from public sources: no source clearly says what to observe.";
    guide.reproduction.expected_observation = [];
    render(<GuideView response={makeGuideResponse(guide)} />);
    expect(screen.getByTestId("reproduction-status")).toHaveTextContent(/only partially established/i);
    expect(screen.getByText("No source says what to observe.")).toBeInTheDocument();
  });

  it("says where a missing section is missing rather than inventing content", () => {
    view({ root_cause: [], impact: [], remediation: [] });
    expect(screen.getByText("No source explains the root cause.")).toBeInTheDocument();
    expect(screen.getByText("No source describes the impact.")).toBeInTheDocument();
    expect(screen.getByText("No source describes a fix or mitigation.")).toBeInTheDocument();
  });

  it("describes how the guide was produced", () => {
    view();
    expect(screen.getByTestId("generation-info")).toHaveTextContent(/assembled from verbatim excerpts.*no language model was used/);
    expect(screen.getByTestId("generation-info")).toHaveTextContent(/not configured on this server/);
  });

  it("names the model when a language model wrote it", () => {
    const guide = makeGuide();
    guide.generation = { ...guide.generation, synthesis_method: "llm", model_version: "claude-test-1", fallback_reason: null };
    render(<GuideView response={makeGuideResponse(guide)} />);
    expect(screen.getByTestId("generation-info")).toHaveTextContent(/language model \(claude-test-1\) and checked against the sources/);
  });
});

describe("hostile content", () => {
  it("renders generated and third-party text as text, never as markup", () => {
    const guide = makeGuide({
      summary: [claim('<img src=x onerror="alert(1)"><script>alert(2)</script>Upgrade now', { source_ids: ["S1"], passage_ids: [] })],
      limitations: ["<b onmouseover=alert(3)>x</b>"],
    });
    guide.evidence = [{ id: "S3-P02", source_id: "S3", kind: "paragraph", text: "<iframe src=//evil.test></iframe>" }];
    const { container } = render(<GuideView response={makeGuideResponse(guide)} />);
    expect(container.querySelector("script, iframe, img[onerror], b[onmouseover]")).toBeNull();
    expect(screen.getByText(/<script>alert\(2\)<\/script>Upgrade now/)).toBeInTheDocument();
  });

  it("never turns an unsafe source URL into a link", () => {
    const guide = makeGuide();
    guide.sources[1] = { ...guide.sources[1]!, url: "javascript:alert(1)" };
    const response = makeGuideResponse(guide);
    response.research_sources[1] = { ...response.research_sources[1]!, url: "data:text/html,<script>alert(1)</script>" };
    const { container } = render(<GuideView response={response} />);
    for (const a of container.querySelectorAll("a[href]")) {
      expect(a.getAttribute("href")).toMatch(/^(https?:\/\/|#)/);
    }
    expect(screen.getByText("AcmeDocs Security Advisory ACME-SA-2099-01")).toBeInTheDocument();
  });

  it("ignores citation IDs that are not real source IDs", () => {
    const guide = makeGuide({ summary: [claim("A claim.", { source_ids: ["S1", "javascript:alert(1)", "../x", "S99999"], passage_ids: [] })] });
    const { container } = render(<GuideView response={makeGuideResponse(guide)} />);
    const hrefs = [...container.querySelectorAll("a[href^='#guide-source-']")].map((a) => a.getAttribute("href"));
    expect(hrefs).not.toContain("#guide-source-javascript:alert(1)");
    expect(hrefs.every((h) => /^#guide-source-S\d{1,3}$/.test(h ?? ""))).toBe(true);
  });
});
