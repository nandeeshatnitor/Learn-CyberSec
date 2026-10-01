/** Mirrors backend/app/schemas/labgen.py (the reviewer API). */

export type CandidateStatusName =
  | "generating"
  | "generation_failed"
  | "spec_only"
  | "building"
  | "build_failed"
  | "validating"
  | "validation_failed"
  | "awaiting_review"
  | "changes_requested"
  | "rejected"
  | "approved";

export type StageName = "pending" | "running" | "passed" | "failed" | "skipped";

export const STATUS_LABELS: Record<CandidateStatusName, string> = {
  generating: "Generating",
  generation_failed: "Generation failed",
  spec_only: "Specification only",
  building: "Building",
  build_failed: "Build failed",
  validating: "Validating",
  validation_failed: "Validation failed",
  awaiting_review: "Awaiting review",
  changes_requested: "Changes requested",
  rejected: "Rejected",
  approved: "Approved",
};

/** The pipeline is still working on these: the list refreshes itself while any is present. */
export const WORKING: readonly CandidateStatusName[] = ["generating", "building", "validating"];

export interface Reviewer {
  name: string;
  labgen_enabled: boolean;
}

export interface CandidateSummary {
  id: string;
  cve_id: string;
  family: string;
  revision: number;
  title: string | null;
  status: CandidateStatusName;
  build_status: StageName;
  validation_status: StageName;
  security_status: StageName;
  progress: string | null;
  source_count: number;
  product: string | null;
  vulnerable_version: string | null;
  reviewer: string | null;
  reviewed_at: string | null;
  requested_by: string;
  created_at: string;
  updated_at: string;
  lab_id: string | null;
  error: string | null;
}

export interface CheckView {
  id: string;
  title: string;
  status: string;
  detail: string;
  seconds: number;
  evidence: string[];
}

export interface FindingView {
  id: string;
  title: string;
  passed: boolean;
  detail: string;
}

export interface ReviewView {
  reviewer: string;
  action: string;
  from_status: string;
  to_status: string;
  notes: string | null;
  at: string;
}

export interface SpecEvidence {
  source_ids: string[];
  excerpt: string;
}

/** The parts of the stored candidate specification the review page shows. */
export interface CandidateSpec {
  cve_id: string;
  title: string;
  affected_software: {
    vendor: string | null;
    product: string | null;
    vulnerable_version: string | null;
    vulnerable_version_basis: string;
    affected_ranges: string[];
    fixed_version: string | null;
    evidence: SpecEvidence[];
  };
  safe_objective: string;
  prerequisites: string[];
  learning_tasks: { id: string; title: string; description: string }[];
  expected_behavior: { vulnerable: string; after_fix: string } | null;
  verification_method: {
    summary: string;
    checks: { id: string; title: string; kind: string; description: string }[];
  } | null;
  remediation_task: { description: string; documented_fix: string | null };
  source_references: {
    id: string;
    title: string;
    url: string | null;
    publisher: string | null;
    source_type: string;
    reliability_level: string;
  }[];
  documented_artifacts: { kind: string; value: string; note: string }[];
  blueprint: {
    id: string;
    version: string;
    params: Record<string, string>;
  } | null;
  generation: {
    method: string;
    generator_version: string;
    model: string | null;
    llm_fallback: string | null;
    overrides: Record<string, string>;
    change_notes: string | null;
  };
  caveats: string[];
  safety_notice: string;
}

export interface CandidateDetail extends CandidateSummary {
  parent_id: string | null;
  spec: CandidateSpec | null;
  files: Record<string, string>;
  build_log: string | null;
  image_tag: string | null;
  checks: CheckView[];
  static_findings: FindingView[];
  runtime_findings: CheckView[];
  reviews: ReviewView[];
  can_approve: boolean;
  blockers: string[];
  generator: Record<string, unknown>;
  review_notes: string | null;
}

export interface VersionView {
  id: string;
  lab_id: string;
  family: string;
  version: number;
  cve_id: string;
  status: "published" | "superseded" | "withdrawn";
  published_at: string;
  published_by: string;
  superseded_by: string | null;
  withdrawn_at: string | null;
  withdrawn_by: string | null;
  withdrawn_reason: string | null;
  content_hash: string;
  candidate_id: string;
}

export const OVERRIDE_FIELDS = [
  ["product", "Product name"],
  ["vulnerable_version", "Vulnerable version"],
  ["fixed_version", "Fixed version"],
  ["header", "Request header (X-…)"],
  ["endpoint", "Endpoint path"],
  ["param", "Query parameter"],
  ["probe_expression", "Probe expression (e.g. 7*7)"],
] as const;
