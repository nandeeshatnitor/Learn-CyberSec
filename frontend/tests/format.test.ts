import { describe, expect, it } from "vitest";

import {
  describeScorer,
  formatDate,
  formatDateTime,
  formatVersionRange,
  hostnameOf,
  productName,
  providerLabel,
  severityVariant,
} from "@/lib/format";
import type { CvssMetric, VersionRange } from "@/lib/types";

const range = (over: Partial<VersionRange>): VersionRange => ({
  status: "affected", version: null, start_including: null, start_excluding: null,
  end_including: null, end_excluding: null, version_type: null, ...over,
});

describe("providerLabel", () => {
  it("names known providers", () => {
    expect(providerLabel("nvd")).toBe("NVD");
    expect(providerLabel("cisa_kev")).toBe("CISA KEV");
    expect(providerLabel("mitre")).toBe("MITRE / CVE Program");
    expect(providerLabel("seed")).toBe("Sample data");
  });

  it("falls back to the raw id for providers added later", () => {
    expect(providerLabel("github_advisories")).toBe("github_advisories");
  });
});

describe("formatVersionRange", () => {
  it.each([
    [{ start_including: "2.0.1", end_excluding: "2.3.1" }, "2.0.1 ≤ version < 2.3.1"],
    [{ start_excluding: "1.0", end_including: "2.0" }, "1.0 < version ≤ 2.0"],
    [{ end_excluding: "2.15.0" }, "version < 2.15.0"],
    [{ end_including: "3.4" }, "version ≤ 3.4"],
    [{ start_including: "4.0" }, "4.0 ≤ version"],
    [{ version: "2.15.0" }, "2.15.0"],
    [{ version: "*" }, "All versions"],
    [{}, "All versions"],
    [{ status: "unaffected" as const, version: "2.15.0" }, "2.15.0 (not affected)"],
    [{ status: "unknown" as const, end_excluding: "9" }, "version < 9 (status unknown)"],
  ])("formats %j as %s", (input, expected) => {
    expect(formatVersionRange(range(input))).toBe(expected);
  });
});

describe("dates", () => {
  it("formats in UTC", () => {
    expect(formatDate("2021-12-10T23:59:59+05:00")).toBe("2021-12-10");
    expect(formatDateTime("2021-12-10T10:15:09.143Z")).toBe("2021-12-10 10:15 UTC");
  });

  it.each([null, undefined, "", "not a date"])("returns null for %j", (value) => {
    expect(formatDate(value)).toBeNull();
    expect(formatDateTime(value)).toBeNull();
  });
});

describe("describeScorer", () => {
  const metric = (over: Partial<CvssMetric>): CvssMetric => ({
    version: "3.1", score: 5, vector: null, severity: "MEDIUM", source: "nvd", scored_by: null, primary: false, ...over,
  });

  it("only calls NVD's primary score an NVD analysis", () => {
    expect(describeScorer(metric({ primary: true, scored_by: "nvd@nist.gov" }))).toBe("NVD analysis");
    expect(describeScorer(metric({ primary: false, scored_by: "134c704f-uuid" }))).toContain("Secondary source");
  });

  it("keeps CNA/ADP labels as reported and never upgrades them to primary", () => {
    expect(describeScorer(metric({ source: "mitre", scored_by: "CNA: apache" }))).toBe("CNA: apache");
    expect(describeScorer(metric({ source: "mitre", scored_by: "ADP: CISA-ADP" }))).toBe("ADP: CISA-ADP");
  });
});

it.each([
  ["CRITICAL", "destructive"], ["high", "destructive"], ["MEDIUM", "warning"], ["LOW", "muted"], ["NONE", "outline"], [null, "outline"],
])("severityVariant(%s) = %s", (severity, variant) => {
  expect(severityVariant(severity)).toBe(variant);
});

it("hostnameOf and productName", () => {
  expect(hostnameOf("https://logging.apache.org/log4j/2.x/security.html")).toBe("logging.apache.org");
  expect(hostnameOf("not a url")).toBeNull();
  expect(productName({ vendor: "apache", product: "log4j" })).toBe("apache log4j");
  expect(productName({ vendor: null, product: "openssl" })).toBe("openssl");
  expect(productName({ vendor: null, product: null })).toBe("Unnamed product");
});
