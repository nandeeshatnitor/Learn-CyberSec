import type {
  Claim,
  LearningGuide,
  ResearchGuideResponse,
  ResearchStatus,
  ResearchStatusName,
} from "@/lib/research-types";

export function makeStatus(status: ResearchStatusName = "not_started", overrides: Partial<ResearchStatus> = {}): ResearchStatus {
  const labels: Record<ResearchStatusName, string> = {
    not_started: "No learning guide has been generated yet",
    queued: "Queued",
    researching: "Researching public sources",
    synthesizing: "Synthesizing the guide",
    ready: "Ready",
    failed: "Failed",
  };
  const active = ["queued", "researching", "synthesizing"].includes(status);
  return {
    cve_id: "CVE-2099-12345",
    status,
    stage: labels[status],
    stage_detail: null,
    run_id: status === "not_started" ? null : "run-1",
    started_at: null,
    completed_at: status === "ready" ? "2026-09-30T07:00:00Z" : null,
    generation_version: "1",
    model_version: null,
    synthesis_method: null,
    sources_discovered: 0,
    source_count: 0,
    error: null,
    cached: false,
    guide_available: status === "ready",
    refresh_available_at: null,
    poll_after_seconds: active ? 3 : null,
    ...overrides,
  };
}

export const claim = (text: string, overrides: Partial<Claim> = {}): Claim => ({
  text,
  evidence_level: "DOCUMENTED",
  source_ids: ["S3"],
  passage_ids: ["S3-P02"],
  notes: [],
  ...overrides,
});

export function makeGuide(overrides: Partial<LearningGuide> = {}): LearningGuide {
  return {
    cve_id: "CVE-2099-12345",
    summary: [claim("AcmeDocs 4.0.0 through 4.2.3 evaluates expressions from a request header.", { source_ids: ["S1"], passage_ids: ["S1-P01"] })],
    vulnerability_class: null,
    affected_versions: [claim("AcmeDocs versions 4.0.0 through 4.2.3 are affected.", { evidence_level: "SUPPORTED_BY_MULTIPLE_SOURCES", source_ids: ["S1", "S3"], passage_ids: [] })],
    root_cause: [claim("The renderer evaluates the header without sanitizing it.")],
    prerequisites: [claim("The preview feature must be enabled.", { evidence_level: "SYNTHESIZED" })],
    reproduction: {
      status: "established",
      statement: "Based on a single public source (S4); nothing confirms it independently.",
      environment: [claim("Use the intentionally vulnerable Docker image.", { source_ids: ["S4"], passage_ids: [] })],
      steps: [
        {
          step: "Start the vulnerable container.",
          evidence_level: "DOCUMENTED",
          source_ids: ["S4"],
          passage_ids: [],
          command: "docker run --rm -p 127.0.0.1:8080:8080 acmedocs/vulnerable:4.2.3",
          command_withheld: null,
          notes: [],
        },
      ],
      expected_observation: [claim("The response body contains 49.", { source_ids: ["S4"], passage_ids: [] })],
      evidence: ["S4"],
    },
    why_it_works: [claim("The expression language can reach the runtime.", { source_ids: ["S4"], passage_ids: [] })],
    impact: [claim("An attacker can execute code as the service account.", { evidence_level: "UNCERTAIN" })],
    remediation: [claim("Upgrade to AcmeDocs 4.2.4 or later.", { source_ids: ["S3"], passage_ids: ["S3-P02"] })],
    confidence: {
      level: "medium",
      score: 0.7,
      reproduction: "medium",
      factors: ["3 independent source group(s) cited", "reproduction: established"],
    },
    limitations: ["Only one document describes the reproduction."],
    sources: [
      { id: "S1", kind: "provider_record", title: "NVD record for CVE-2099-12345", url: "https://nvd.nist.gov/vuln/detail/CVE-2099-12345", publisher: "NVD", source_type: "nvd", reliability_level: "official", retrieved_at: "2026-09-30T06:00:00Z", content_hash: null, independent_group: "cve-record", cited_by: 2 },
      { id: "S3", kind: "document", title: "AcmeDocs Security Advisory ACME-SA-2099-01", url: "https://advisories.acme-vendor.test/ACME-SA-2099-01", publisher: "advisories.acme-vendor.test", source_type: "vendor_advisory", reliability_level: "high", retrieved_at: "2026-09-30T06:01:00Z", content_hash: "a".repeat(64), independent_group: "acme-vendor.test", cited_by: 3 },
      { id: "S4", kind: "document", title: "Dissecting CVE-2099-12345", url: "https://blog.example-security.test/post", publisher: "blog.example-security.test", source_type: "security_blog", reliability_level: "low", retrieved_at: "2026-09-30T06:01:00Z", content_hash: "b".repeat(64), independent_group: "example-security.test", cited_by: 4 },
    ],
    evidence: [
      { id: "S3-P02", source_id: "S3", kind: "paragraph", text: "Upgrade to AcmeDocs 4.2.4 or later. As a workaround, disable the preview feature." },
    ],
    generation: {
      generation_version: "1",
      synthesis_method: "extractive",
      model_version: null,
      generated_at: "2026-09-30T07:00:00Z",
      fallback_reason: "llm_not_configured",
    },
    validation: { claims_kept: 8, claims_removed: 0, claims_downgraded: 1, by_level: {}, issues: [] },
    safety_notice:
      "For education and authorized testing only. Reproduce vulnerabilities in local environments, intentionally vulnerable software or authorized lab environments that you control.",
    ...overrides,
  };
}

export function makeGuideResponse(
  guide: LearningGuide = makeGuide(),
  overrides: Partial<ResearchGuideResponse> = {},
): ResearchGuideResponse {
  return {
    ...makeStatus("ready", { sources_discovered: 11, source_count: 2 }),
    guide,
    research_sources: [
      { sid: "S1", url: "https://nvd.nist.gov/vuln/detail/CVE-2099-12345", title: "NVD record for CVE-2099-12345", publisher: "NVD", source_type: "nvd", reliability_level: "official", status: "extracted", detail: null, used: true, retrieved_at: null, content_hash: null },
      { sid: "S3", url: "https://advisories.acme-vendor.test/ACME-SA-2099-01", title: "AcmeDocs Security Advisory", publisher: null, source_type: "vendor_advisory", reliability_level: "high", status: "extracted", detail: null, used: true, retrieved_at: null, content_hash: null },
      { sid: null, url: "https://private.example-blocked.test/x", title: "https://private.example-blocked.test/x", publisher: null, source_type: "other", reliability_level: "low", status: "blocked", detail: "robots_disallowed", used: false, retrieved_at: null, content_hash: null },
      { sid: null, url: "https://notes.example-attacker.test/n", title: "quick notes", publisher: null, source_type: "other", reliability_level: "low", status: "excluded", detail: "hidden_prompt_injection", used: false, retrieved_at: null, content_hash: null },
    ],
    ...overrides,
  };
}
