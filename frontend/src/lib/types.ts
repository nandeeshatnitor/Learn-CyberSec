/** Mirrors the backend Pydantic schemas (backend/app/schemas). */

export type SourceType =
  | "nvd"
  | "mitre"
  | "vendor_advisory"
  | "github_advisory"
  | "cert"
  | "cisa"
  | "exploit_db"
  | "research_blog"
  | "other";

export type ReliabilityLevel = "official" | "high" | "medium" | "low" | "unverified";

export interface Source {
  id: string;
  source_type: SourceType;
  title: string;
  url: string;
  publisher: string | null;
  retrieved_at: string | null;
  reliability_level: ReliabilityLevel;
}

export interface CveReference {
  source: Source;
  tags: string[];
}

export interface AffectedProduct {
  vendor?: string;
  product?: string;
  versions?: string;
}

export interface CveSummary {
  id: string;
  cve_id: string;
  description: string;
  published_at: string | null;
  cvss_score: number | null;
  severity: string | null;
  data_origin: "seed" | "nvd";
}

export interface Cve extends CveSummary {
  modified_at: string | null;
  cvss_vector: string | null;
  cwes: string[];
  affected_products: AffectedProduct[];
  references: CveReference[];
  created_at: string;
  updated_at: string;
}

export interface CveSearchResponse {
  query: string;
  items: CveSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface HealthResponse {
  status: "ok" | "degraded" | "unhealthy";
  version: string;
  environment: string;
  checks: Record<string, { status: string }>;
}
