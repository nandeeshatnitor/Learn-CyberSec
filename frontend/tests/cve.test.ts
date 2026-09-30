import { describe, expect, it } from "vitest";

import { cweUrl, MAX_QUERY_LENGTH, normalizeCveId, parseCveIdParam, sanitizeQuery } from "@/lib/cve";

describe("normalizeCveId", () => {
  it.each([
    ["CVE-2021-44228", "CVE-2021-44228"],
    [" cve-2014-0160 ", "CVE-2014-0160"],
  ])("accepts %s", (input, expected) => {
    expect(normalizeCveId(input)).toBe(expected);
  });

  it.each(["", "CVE-2021-1", "CVE-21-44228", "CVE-2021-44228; rm -rf /", "CVE-2021-٤٤٢٢٨", "../x"])(
    "rejects %j",
    (input) => {
      expect(normalizeCveId(input)).toBeNull();
    },
  );
});

describe("parseCveIdParam", () => {
  it("decodes and normalises", () => {
    expect(parseCveIdParam("cve-2021-44228")).toBe("CVE-2021-44228");
  });

  it("does not throw on malformed percent-escapes", () => {
    expect(parseCveIdParam("%E0%A4%A")).toBeNull();
  });

  it("rejects encoded injection attempts", () => {
    expect(parseCveIdParam("CVE-2021-44228%00")).toBeNull();
  });
});

describe("sanitizeQuery", () => {
  it("removes control characters and trims", () => {
    expect(sanitizeQuery("  log\u0000\u001b4j  ")).toBe("log4j");
  });

  it("caps length", () => {
    expect(sanitizeQuery("a".repeat(500))).toHaveLength(MAX_QUERY_LENGTH);
  });

  it("handles undefined", () => {
    expect(sanitizeQuery(undefined)).toBe("");
  });
});

describe("cweUrl", () => {
  it("links well-formed CWE ids", () => {
    expect(cweUrl("CWE-502")).toBe("https://cwe.mitre.org/data/definitions/502.html");
  });

  it.each(["CWE-", "CWE-1/../x", "cwe-1", "NVD-CWE-Other", "javascript:alert(1)"])("ignores %j", (v) => {
    expect(cweUrl(v)).toBeNull();
  });
});
