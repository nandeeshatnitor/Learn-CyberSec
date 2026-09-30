import { SafeLink } from "@/components/safe-link";
import { Badge } from "@/components/ui/badge";
import type { ResearchGuideResponse, ResearchSourceOutcome } from "@/lib/research-types";

const STATUS_LABEL: Record<string, string> = {
  extracted: "Used",
  irrelevant: "Not relevant",
  duplicate: "Duplicate",
  blocked: "Not retrieved",
  excluded: "Excluded",
  skipped: "Skipped",
  failed: "Could not be read",
  retrieved: "Retrieved",
  discovered: "Not retrieved",
};

const DETAIL_TEXT: Record<string, string> = {
  robots_disallowed: "The site's robots.txt does not allow automated access.",
  robots_unavailable: "The site's robots.txt could not be checked, so it was left alone.",
  crawl_delay_too_long: "The site asks crawlers to wait too long between requests.",
  hidden_prompt_injection: "The page contained hidden text addressed to AI assistants, so none of it was used.",
  no_cve_or_product_match: "The page does not mention this CVE or its product.",
  about_other_cves: "The page is a roundup of other vulnerabilities.",
  no_relevant_passages: "No passage on the page was technically relevant.",
  no_readable_text: "No readable text could be extracted.",
  covered_by_structured_providers: "Already covered by the structured CVE records.",
  unsupported_file_type: "Not a text page (for example a PDF, archive or patch file).",
  code_hosting_page: "A code-hosting page; repositories are read through their README instead.",
  over_source_budget: "Skipped: the per-guide retrieval limit was reached.",
  over_source_limit: "Skipped: the per-guide source limit was reached.",
  time_budget: "Skipped: the research time limit was reached.",
  passages_duplicated_elsewhere: "Its relevant passages were already cited from a better source.",
  not_found: "The page no longer exists.",
  access_denied: "The site refused access.",
  rate_limited: "The site asked us to slow down.",
  server_error: "The site returned an error.",
  unsupported_content_type: "Not a text document.",
  binary_content: "Binary content, not text.",
  too_large: "Too large to process safely.",
  timeout: "The site took too long to answer.",
  extraction_failed: "The page could not be parsed safely.",
};

function label(source: ResearchSourceOutcome): string {
  if (source.detail?.startsWith("duplicate_of:")) return "This page is a copy of another source.";
  return (source.detail && DETAIL_TEXT[source.detail]) || "";
}

export function ResearchSources({ response }: { response: ResearchGuideResponse }) {
  const used = response.research_sources.filter((s) => s.used);
  const other = response.research_sources.filter((s) => !s.used);
  return (
    <div className="space-y-4 text-sm">
      <p data-testid="sources-summary">
        {response.sources_discovered} public source{response.sources_discovered === 1 ? "" : "s"} found,{" "}
        {response.source_count} retrieved document{response.source_count === 1 ? "" : "s"} used
        {used.length > response.source_count ? " (plus the structured CVE records)" : ""}. Only short
        relevant excerpts, hashes and citations are stored, never whole pages.
      </p>
      <ul className="space-y-2" data-testid="used-sources">
        {used.map((source) => (
          <li key={`${source.sid}-${source.url}`}>
            <span className="mr-2 font-mono text-muted-foreground">[{source.sid}]</span>
            {source.url ? <SafeLink href={source.url}>{source.title}</SafeLink> : <span>{source.title}</span>}
            <span className="ml-2 space-x-1">
              <Badge variant="muted">{source.source_type.replace(/_/g, " ")}</Badge>
              <Badge variant="outline">{source.reliability_level}</Badge>
            </span>
          </li>
        ))}
      </ul>
      {other.length > 0 && (
        <details>
          <summary className="cursor-pointer select-none text-muted-foreground">
            {other.length} other source{other.length === 1 ? "" : "s"} considered but not used
          </summary>
          <ul className="mt-2 space-y-2" data-testid="unused-sources">
            {other.map((source, index) => (
              <li key={`${index}-${source.url}`}>
                {source.url ? <SafeLink href={source.url}>{source.title}</SafeLink> : <span>{source.title}</span>}
                <Badge variant="outline" className="ml-2">
                  {STATUS_LABEL[source.status] ?? source.status}
                </Badge>
                {label(source) && <span className="block text-xs text-muted-foreground">{label(source)}</span>}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
