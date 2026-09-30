/** Mirrors the backend Pydantic schemas (backend/app/schemas). Provider IDs are plain strings. */

export type Severity = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface SourceAttribution {
  provider: string;
  name: string;
  publisher: string;
  source_type: string;
  reliability_level: string;
  /** The provider's own page for this CVE. */
  url: string | null;
  retrieved_at: string;
  /** True when this is an expired copy served because the provider failed. */
  stale: boolean;
}

export interface CvssMetric {
  version: string;
  score: number;
  vector: string | null;
  severity: Severity | null;
  source: string;
  scored_by: string | null;
  primary: boolean;
}

export interface Cwe {
  id: string;
  name: string | null;
  sources: string[];
}

export interface VersionRange {
  status: "affected" | "unaffected" | "unknown";
  version: string | null;
  start_including: string | null;
  start_excluding: string | null;
  end_including: string | null;
  end_excluding: string | null;
  version_type: string | null;
}

export interface AffectedProduct {
  vendor: string | null;
  product: string | null;
  source: string;
  cpe: string | null;
  platforms: string[];
  versions: VersionRange[];
}

export interface Reference {
  /** Exactly as published by the source. Render only through SafeLink. */
  url: string;
  title: string | null;
  tags: string[];
  sources: string[];
}

export interface KevInfo {
  source: string;
  vulnerability_name: string | null;
  date_added: string | null;
  due_date: string | null;
  required_action: string | null;
  short_description: string | null;
  known_ransomware_campaign_use: string | null;
  notes: string | null;
}

export interface CveRecord {
  cve_id: string;
  description: string | null;
  vuln_status: string | null;
  published_at: string | null;
  modified_at: string | null;
  severity: Severity | null;
  cvss: CvssMetric | null;
  cvss_metrics: CvssMetric[];
  cwes: Cwe[];
  affected_products: AffectedProduct[];
  references: Reference[];
  /** null = unknown (the KEV catalogue could not be consulted); false = consulted, not listed. */
  known_exploited: boolean | null;
  kev: KevInfo | null;
  sources: SourceAttribution[];
  /** field name -> providers that supplied it */
  field_sources: Record<string, string[]>;
  retrieved_at: string | null;
  data_origin: "providers" | "seed";
}

export type ProviderStatusName =
  | "ok"
  | "stale"
  | "not_found"
  | "unavailable"
  | "rate_limited"
  | "circuit_open"
  | "disabled"
  | "unsupported";

export interface ProviderStatus {
  provider: string;
  name: string;
  status: ProviderStatusName;
  retrieved_at: string | null;
  from_cache: boolean;
  message: string | null;
}

export interface ResponseMeta {
  providers: ProviderStatus[];
  warnings: string[];
  served_from: "providers" | "database" | "fallback";
}

export interface CveDetail extends CveRecord {
  meta: ResponseMeta;
}

export interface CveSearchResponse {
  query: string;
  query_type: "cve_id" | "partial_cve_id" | "keyword";
  items: CveRecord[];
  total: number;
  page: number;
  limit: number;
  pages: number;
  filters: { severity?: Severity | null; known_exploited?: boolean | null };
  meta: ResponseMeta;
}

export interface HealthResponse {
  status: "ok" | "degraded" | "unhealthy";
  version: string;
  environment: string;
  checks: Record<string, { status: string }>;
}
