import type { CveDetail, CveRecord, CveSearchResponse, ResponseMeta } from "@/lib/types";

export const okMeta: ResponseMeta = {
  providers: [
    { provider: "nvd", name: "NVD", status: "ok", retrieved_at: "2026-09-30T06:00:00Z", from_cache: false, message: null },
    { provider: "mitre", name: "MITRE / CVE Program", status: "ok", retrieved_at: "2026-09-30T06:00:00Z", from_cache: false, message: null },
    { provider: "cisa_kev", name: "CISA KEV", status: "ok", retrieved_at: "2026-09-30T06:00:00Z", from_cache: true, message: null },
  ],
  warnings: [],
  served_from: "providers",
};

export function makeCve(overrides: Partial<CveRecord> = {}): CveRecord {
  const nvdMetric = {
    version: "3.1", score: 10, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    severity: "CRITICAL" as const, source: "nvd", scored_by: "nvd@nist.gov", primary: true,
  };
  return {
    cve_id: "CVE-2021-44228",
    description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.",
    vuln_status: "Analyzed",
    published_at: "2021-12-10T10:15:09.143Z",
    modified_at: "2025-05-05T17:15:00Z",
    severity: "CRITICAL",
    cvss: nvdMetric,
    cvss_metrics: [
      nvdMetric,
      { ...nvdMetric, source: "mitre", scored_by: "CNA: apache", primary: false },
      { version: "2.0", score: 9.3, vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C", severity: "HIGH", source: "nvd", scored_by: "nvd@nist.gov", primary: true },
    ],
    cwes: [
      { id: "CWE-502", name: "Deserialization of Untrusted Data", sources: ["nvd", "mitre"] },
      { id: "NVD-CWE-Other", name: null, sources: ["nvd"] },
    ],
    affected_products: [
      {
        vendor: "apache", product: "log4j", source: "nvd", cpe: null, platforms: [],
        versions: [
          { status: "affected", version: null, start_including: "2.0.1", start_excluding: null, end_including: null, end_excluding: "2.3.1", version_type: "cpe" },
          { status: "affected", version: "2.0 beta9", start_including: null, start_excluding: null, end_including: null, end_excluding: null, version_type: "cpe" },
        ],
      },
      {
        vendor: "Apache Software Foundation", product: "Apache Log4j2", source: "mitre", cpe: null, platforms: [],
        versions: [{ status: "unaffected", version: "2.15.0", start_including: null, start_excluding: null, end_including: null, end_excluding: null, version_type: "custom" }],
      },
    ],
    references: [
      { url: "https://logging.apache.org/log4j/2.x/security.html", title: "Apache Log4j security page", tags: ["Vendor Advisory"], sources: ["nvd", "mitre"] },
      { url: "http://www.openwall.com/lists/oss-security/2021/12/10/1", title: null, tags: ["Mailing List"], sources: ["nvd"] },
    ],
    known_exploited: true,
    kev: {
      source: "cisa_kev", vulnerability_name: "Apache Log4j2 Remote Code Execution Vulnerability",
      date_added: "2021-12-10", due_date: "2021-12-24", required_action: "Apply updates per vendor instructions.",
      short_description: "Log4j2 JNDI features allow remote code execution.", known_ransomware_campaign_use: "Known", notes: "https://example.com/notes",
    },
    sources: [
      { provider: "nvd", name: "NVD", publisher: "NIST National Vulnerability Database", source_type: "nvd", reliability_level: "official", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", retrieved_at: "2026-09-30T06:00:00Z", stale: false },
      { provider: "cisa_kev", name: "CISA KEV", publisher: "CISA", source_type: "cisa", reliability_level: "official", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", retrieved_at: "2026-09-30T06:00:00Z", stale: false },
    ],
    field_sources: {
      description: ["nvd"], vuln_status: ["nvd"], published_at: ["nvd"], modified_at: ["nvd"],
      cvss: ["nvd"], severity: ["nvd"], cvss_metrics: ["nvd", "mitre"], cwes: ["nvd", "mitre"],
      affected_products: ["nvd", "mitre"], references: ["nvd", "mitre"], kev: ["cisa_kev"], known_exploited: ["cisa_kev"],
    },
    retrieved_at: "2026-09-30T06:00:00Z",
    data_origin: "providers",
    ...overrides,
  };
}

export function makeDetail(overrides: Partial<CveRecord> = {}, meta: ResponseMeta = okMeta): CveDetail {
  return { ...makeCve(overrides), meta };
}

/** A record with nothing but its ID, as when only a stub is available. */
export function makeBareCve(overrides: Partial<CveRecord> = {}): CveRecord {
  return makeCve({
    description: null, vuln_status: null, published_at: null, modified_at: null, severity: null, cvss: null,
    cvss_metrics: [], cwes: [], affected_products: [], references: [], known_exploited: null, kev: null,
    sources: [], field_sources: {}, retrieved_at: null, ...overrides,
  });
}

export function makeSearch(overrides: Partial<CveSearchResponse> = {}): CveSearchResponse {
  return {
    query: "log4j", query_type: "keyword", items: [makeCve()], total: 37, page: 1, limit: 20, pages: 2,
    filters: { severity: null, known_exploited: null }, meta: okMeta, ...overrides,
  };
}
