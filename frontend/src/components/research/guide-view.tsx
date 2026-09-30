import { ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";

import { Citations, EvidenceBadge, EvidenceDetails, EvidenceLegend } from "@/components/research/evidence";
import { ResearchSources } from "@/components/research/research-sources";
import { SafeLink } from "@/components/safe-link";
import { SectionCard } from "@/components/section-card";
import { Badge } from "@/components/ui/badge";
import { formatDateTime } from "@/lib/format";
import type {
  Claim,
  ConfidenceLevel,
  LearningGuide,
  ReproStep,
  ResearchGuideResponse,
} from "@/lib/research-types";

const CONFIDENCE_LABEL: Record<ConfidenceLevel, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
  insufficient: "Insufficient evidence",
};

const WITHHELD_REASON: Record<string, string> = {
  pipes_download_to_interpreter:
    "This command downloads and runs code in one step, so it is not shown as runnable.",
  destructive_command: "This command is destructive, so it is not shown as runnable.",
  targets_non_local_host:
    "This command targets a system that is not a local or lab address, so it is not shown as runnable.",
};

function SubHeading({ n, children }: { n: number; children: ReactNode }) {
  return (
    <h3 className="mt-5 text-base font-semibold first:mt-0">
      <span className="mr-2 font-mono text-muted-foreground">{n}.</span>
      {children}
    </h3>
  );
}

function Empty({ children }: { children: ReactNode }) {
  return <p className="mt-2 text-sm text-muted-foreground">{children}</p>;
}

function ClaimList({ claims, guide, none }: { claims: Claim[]; guide: LearningGuide; none: string }) {
  if (claims.length === 0) return <Empty>{none}</Empty>;
  return (
    <ul className="mt-2 space-y-3">
      {claims.map((claim, index) => (
        <li key={`${index}-${claim.text.slice(0, 24)}`} data-testid="claim">
          {/* Plain text: claim wording is generated from third-party pages and never rendered as HTML. */}
          <span className="leading-relaxed">{claim.text}</span>{" "}
          <EvidenceBadge level={claim.evidence_level} />
          <Citations ids={claim.source_ids} guide={guide} />
          {claim.notes.length > 0 && (
            <span className="mt-0.5 block text-xs text-muted-foreground">{claim.notes.join(" ")}</span>
          )}
          <EvidenceDetails passageIds={claim.passage_ids} guide={guide} />
        </li>
      ))}
    </ul>
  );
}

function StepList({ steps, guide }: { steps: ReproStep[]; guide: LearningGuide }) {
  if (steps.length === 0) return <Empty>No procedure could be established from the sources.</Empty>;
  return (
    <ol className="mt-2 list-decimal space-y-4 pl-6">
      {steps.map((step, index) => (
        <li key={`${index}-${step.step.slice(0, 24)}`} data-testid="repro-step">
          <span className="leading-relaxed">{step.step}</span> <EvidenceBadge level={step.evidence_level} />
          <Citations ids={step.source_ids} guide={guide} />
          {step.command && (
            <div className="mt-2">
              <pre
                className="overflow-x-auto rounded-md border bg-muted p-3 text-sm"
                aria-label="Command quoted from a source (shown as text; not run by this platform)"
              >
                <code>{step.command}</code>
              </pre>
              <p className="mt-1 text-xs text-muted-foreground">
                Quoted from the source. Nothing on this site runs it: read it, then run it only in
                your own lab.
              </p>
            </div>
          )}
          {step.command_withheld && (
            <p className="mt-2 flex items-start gap-2 rounded-md border border-warning/40 bg-warning/10 p-2 text-xs">
              <ShieldAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
              <span>
                Command withheld.{" "}
                {WITHHELD_REASON[step.command_withheld] ?? "It did not pass the platform's safety checks."}
              </span>
            </p>
          )}
          {step.notes.length > 0 && (
            <span className="mt-0.5 block text-xs text-muted-foreground">{step.notes.join(" ")}</span>
          )}
          <EvidenceDetails passageIds={step.passage_ids} guide={guide} />
        </li>
      ))}
    </ol>
  );
}

function GenerationInfo({ response }: { response: ResearchGuideResponse }) {
  const { guide } = response;
  const method =
    guide.generation.synthesis_method === "llm"
      ? `written by a language model (${guide.generation.model_version ?? "unknown model"}) and checked against the sources`
      : "assembled from verbatim excerpts of the sources (no language model was used)";
  return (
    <p className="text-sm text-muted-foreground" data-testid="generation-info">
      Generated {formatDateTime(guide.generation.generated_at) ?? "recently"}: {method}. Every statement below
      lists the sources it comes from and how well they support it.
      {guide.generation.fallback_reason === "llm_not_configured" && " (Language-model synthesis is not configured on this server.)"}
      {guide.generation.fallback_reason &&
        guide.generation.fallback_reason !== "llm_not_configured" &&
        " (Language-model synthesis was unavailable or its output did not pass checking, so excerpts are shown instead.)"}
    </p>
  );
}

export function GuideView({ response }: { response: ResearchGuideResponse }) {
  const { guide } = response;
  const repro = guide.reproduction;
  return (
    <div className="space-y-6" data-testid="guide-view">
      <div className="space-y-3 rounded-lg border border-warning/40 bg-warning/10 p-4 text-sm" role="note">
        <p className="flex items-start gap-2">
          <ShieldAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
          <span>{guide.safety_notice}</span>
        </p>
      </div>
      <GenerationInfo response={response} />

      <SectionCard id="research-sources" title="Research sources">
        <ResearchSources response={response} />
      </SectionCard>

      <SectionCard id="confidence" title="Confidence">
        <div className="flex flex-wrap items-center gap-3">
          <Badge
            variant={guide.confidence.level === "high" || guide.confidence.level === "medium" ? "default" : "warning"}
            data-testid="confidence-level"
          >
            Overall: {CONFIDENCE_LABEL[guide.confidence.level]}
          </Badge>
          <Badge variant="outline" data-testid="reproduction-confidence">
            Reproduction: {CONFIDENCE_LABEL[guide.confidence.reproduction]}
          </Badge>
          <span className="text-sm text-muted-foreground">score {guide.confidence.score.toFixed(2)}</span>
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          Calculated by the platform from how many independent sources support the guide, how
          reliable they are and how much of it they state directly. It is not the model&apos;s own
          opinion.
        </p>
        <ul className="mt-3 list-disc space-y-1 pl-5 text-sm">
          {guide.confidence.factors.map((factor) => (
            <li key={factor}>{factor}</li>
          ))}
        </ul>
        {guide.limitations.length > 0 && (
          <div className="mt-4" data-testid="limitations">
            <h3 className="text-sm font-semibold">Gaps and uncertainty</h3>
            <ul className="mt-1 list-disc space-y-1 pl-5 text-sm">
              {guide.limitations.map((text) => (
                <li key={text}>{text}</li>
              ))}
            </ul>
          </div>
        )}
        <div className="mt-4">
          <EvidenceLegend />
        </div>
      </SectionCard>

      <SectionCard id="learning-guide" title="Learning guide">
        <SubHeading n={1}>What is the vulnerability?</SubHeading>
        <ClaimList claims={guide.summary} guide={guide} none="No source gave a usable summary." />
        {guide.vulnerability_class && (
          <div className="mt-2 text-sm">
            <span className="text-muted-foreground">Class: </span>
            <ClaimList claims={[guide.vulnerability_class]} guide={guide} none="" />
          </div>
        )}
        <SubHeading n={2}>Why does it happen?</SubHeading>
        <ClaimList claims={guide.root_cause} guide={guide} none="No source explains the root cause." />
        <SubHeading n={3}>Affected versions</SubHeading>
        <ClaimList claims={guide.affected_versions} guide={guide} none="No source states the affected versions in a verifiable way." />
        <SubHeading n={4}>Prerequisites</SubHeading>
        <ClaimList claims={guide.prerequisites} guide={guide} none="No source states the conditions needed." />
      </SectionCard>

      <SectionCard id="reproduction" title="Reproduction" unavailable={repro.status === "not_established"}>
        <p
          className="rounded-md border p-3 text-sm"
          data-testid="reproduction-status"
          data-status={repro.status}
        >
          <strong className="mr-1">
            {repro.status === "established" && "Reproduction established from public sources."}
            {repro.status === "partial" && "Reproduction only partially established."}
            {repro.status === "not_established" && "Reproduction not established."}
          </strong>
          {repro.statement}
        </p>
        {repro.status !== "not_established" && (
          <>
            <SubHeading n={5}>Safe, local reproduction environment</SubHeading>
            <ClaimList claims={repro.environment} guide={guide} none="No source describes the environment to use." />
            <SubHeading n={6}>Reproduction procedure</SubHeading>
            <StepList steps={repro.steps} guide={guide} />
            <SubHeading n={7}>What to observe</SubHeading>
            <ClaimList claims={repro.expected_observation} guide={guide} none="No source says what to observe." />
          </>
        )}
      </SectionCard>

      <SectionCard id="technical-explanation" title="Technical explanation">
        <SubHeading n={8}>Why the reproduction works</SubHeading>
        <ClaimList claims={guide.why_it_works} guide={guide} none="No source explains why it works." />
        <SubHeading n={9}>Impact</SubHeading>
        <ClaimList claims={guide.impact} guide={guide} none="No source describes the impact." />
      </SectionCard>

      <SectionCard id="remediation" title="Remediation">
        <SubHeading n={10}>How to fix or mitigate it</SubHeading>
        <ClaimList claims={guide.remediation} guide={guide} none="No source describes a fix or mitigation." />
      </SectionCard>

      <SectionCard id="guide-references" title="References used by this guide">
        <SubHeading n={11}>Sources</SubHeading>
        <ol className="mt-2 space-y-3" data-testid="guide-sources">
          {guide.sources.map((source) => (
            <li key={source.id} id={/^S\d{1,3}$/.test(source.id) ? `guide-source-${source.id}` : undefined} className="text-sm">
              <span className="mr-2 font-mono text-muted-foreground">[{source.id}]</span>
              {source.url ? <SafeLink href={source.url}>{source.title}</SafeLink> : <span>{source.title}</span>}
              <span className="ml-2 space-x-1">
                <Badge variant="muted">{source.source_type.replace(/_/g, " ")}</Badge>
                <Badge variant="outline">{source.reliability_level}</Badge>
              </span>
              <span className="block text-xs text-muted-foreground">
                {source.publisher ? `${source.publisher}. ` : ""}
                {source.kind === "provider_record" ? "Structured record. " : ""}
                {source.retrieved_at ? `Retrieved ${formatDateTime(source.retrieved_at)}. ` : ""}
                Cited by {source.cited_by} statement{source.cited_by === 1 ? "" : "s"}.
                {source.content_hash ? ` Content hash ${source.content_hash.slice(0, 12)}…` : ""}
              </span>
            </li>
          ))}
        </ol>
      </SectionCard>
    </div>
  );
}
