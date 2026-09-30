import { describe, expect, it } from "vitest";

import { buildSearchHref, MAX_PAGE, parseSearchParams } from "@/lib/search-params";

describe("parseSearchParams", () => {
  it("applies safe defaults", () => {
    expect(parseSearchParams({})).toEqual({ q: "", page: 1, severity: undefined, knownExploited: false });
  });

  it("reads valid values, case-insensitively for severity", () => {
    expect(parseSearchParams({ q: " apache ", page: "3", severity: "high", known_exploited: "true" })).toEqual({
      q: "apache", page: 3, severity: "HIGH", knownExploited: true,
    });
  });

  it.each(["0", "-2", "abc", "1.5x", "", "NaN"])("falls back to page 1 for %j", (page) => {
    expect(parseSearchParams({ page }).page).toBe(1);
  });

  it("caps the page number", () => {
    expect(parseSearchParams({ page: "99999" }).page).toBe(MAX_PAGE);
  });

  it.each(["NONE", "URGENT", "high; drop", "<script>"])("ignores an invalid severity %j", (severity) => {
    expect(parseSearchParams({ severity }).severity).toBeUndefined();
  });

  it("only treats the literal string 'true' as enabling the KEV filter", () => {
    expect(parseSearchParams({ known_exploited: "1" }).knownExploited).toBe(false);
    expect(parseSearchParams({ known_exploited: "false" }).knownExploited).toBe(false);
  });

  it("takes the first value of repeated parameters and sanitises the query", () => {
    expect(parseSearchParams({ q: ["first\u0000", "second"] }).q).toBe("first");
    expect(parseSearchParams({ q: "x".repeat(500) }).q).toHaveLength(100);
  });
});

describe("buildSearchHref", () => {
  it("omits defaults", () => {
    expect(buildSearchHref({ q: "apache" })).toBe("/cves?q=apache");
    expect(buildSearchHref({ q: "apache", page: 1 })).toBe("/cves?q=apache");
  });

  it("includes filters and page, and encodes the query", () => {
    expect(buildSearchHref({ q: "remote code execution", page: 2, severity: "HIGH", knownExploited: true })).toBe(
      "/cves?q=remote+code+execution&page=2&severity=HIGH&known_exploited=true",
    );
    expect(buildSearchHref({ q: "a&b=c" })).toBe("/cves?q=a%26b%3Dc");
  });
});
