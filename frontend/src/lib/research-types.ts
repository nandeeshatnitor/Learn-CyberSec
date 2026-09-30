/** Mirrors backend/app/schemas/research.py and backend/app/research/synthesis/schema.py. */

export type ResearchStatusName =
  | "not_started"
  | "queued"
  | "researching"
  | "synthesizing"
  | "ready"
  | "failed";

export type EvidenceLevel =
  | "DOCUMENTED"
  | "SUPPORTED_BY_MULTIPLE_SOURCES"
  | "SYNTHESIZED"
  | "UNCERTAIN";

export type ReproductionStatus = "established" | "partial" | "not_established";
export type ConfidenceLevel = "high" | "medium" | "low" | "insufficient";

export interface ResearchStatus {
  cve_id: string;
  status: ResearchStatusName;
  /** Human label for `status` ("Queued", "Researching public sources", ...). */
  stage: string;
  stage_detail: string | null;
  run_id: string | null;
  started_at: string | null;
  completed_at: string | null;
  generation_version: string | null;
  model_version: string | null;
  synthesis_method: "llm" | "extractive" | null;
  sources_discovered: number;
  source_count: number;
  error: { code: string; message: string } | null;
  /** A stored guide was reused instead of researching again. */
  cached: boolean;
  guide_available: boolean;
  refresh_available_at: string | null;
  poll_after_seconds: number | null;
}

export interface Claim {
  text: string;
  evidence_level: EvidenceLevel;
  source_ids: string[];
  passage_ids: string[];
  notes: string[];
}

export interface ReproStep {
  step: string;
  evidence_level: EvidenceLevel;
  source_ids: string[];
  passage_ids: string[];
  /** Displayed as text only. The platform never runs it. */
  command: string | null;
  command_withheld: string | null;
  notes: string[];
}

export interface Reproduction {
  status: ReproductionStatus;
  statement: string;
  environment: Claim[];
  steps: ReproStep[];
  expected_observation: Claim[];
  evidence: string[];
}

export interface Confidence {
  level: ConfidenceLevel;
  score: number;
  reproduction: ConfidenceLevel;
  factors: string[];
}

export interface SourceCitation {
  id: string;
  kind: "document" | "provider_record";
  title: string;
  url: string | null;
  publisher: string | null;
  source_type: string;
  reliability_level: string;
  retrieved_at: string | null;
  content_hash: string | null;
  independent_group: string;
  cited_by: number;
}

export interface EvidencePassage {
  id: string;
  source_id: string;
  kind: string;
  text: string;
}

export interface LearningGuide {
  cve_id: string;
  summary: Claim[];
  vulnerability_class: Claim | null;
  affected_versions: Claim[];
  root_cause: Claim[];
  prerequisites: Claim[];
  reproduction: Reproduction;
  why_it_works: Claim[];
  impact: Claim[];
  remediation: Claim[];
  confidence: Confidence;
  limitations: string[];
  sources: SourceCitation[];
  evidence: EvidencePassage[];
  generation: {
    generation_version: string;
    synthesis_method: "llm" | "extractive";
    model_version: string | null;
    generated_at: string;
    fallback_reason: string | null;
  };
  validation: {
    claims_kept: number;
    claims_removed: number;
    claims_downgraded: number;
    by_level: Record<string, number>;
    issues: string[];
  };
  safety_notice: string;
}

export interface ResearchSourceOutcome {
  sid: string | null;
  url: string | null;
  title: string;
  publisher: string | null;
  source_type: string;
  reliability_level: string;
  status: string;
  detail: string | null;
  used: boolean;
  retrieved_at: string | null;
  content_hash: string | null;
}

export interface ResearchGuideResponse extends ResearchStatus {
  guide: LearningGuide;
  research_sources: ResearchSourceOutcome[];
}

/** Uniform error body returned by the same-origin proxy (and by the backend). */
export interface ResearchProblem {
  kind: "not_found" | "invalid" | "rate_limited" | "disabled" | "unavailable" | "forbidden";
  message: string;
  retryAfter?: number;
}
