import { SectionCard, UnavailableNotice } from "@/components/section-card";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { describeScorer, providerLabel } from "@/lib/format";
import type { CvssMetric, CveRecord } from "@/lib/types";

const sameMetric = (a: CvssMetric, b: CvssMetric) =>
  a.source === b.source &&
  a.version === b.version &&
  a.vector === b.vector &&
  a.scored_by === b.scored_by &&
  a.score === b.score;

const isHeadline = (metric: CvssMetric, headline: CvssMetric | null) =>
  headline !== null && sameMetric(metric, headline);

/** CVSS: the headline metric first, then every metric that was reported and by whom. */
export function CvssSection({ cve }: { cve: CveRecord }) {
  if (cve.cvss_metrics.length === 0) {
    return (
      <SectionCard id="cvss" title="CVSS" unavailable>
        <UnavailableNotice>No CVSS score was reported by the available sources.</UnavailableNotice>
      </SectionCard>
    );
  }
  const headline = cve.cvss;
  return (
    <SectionCard id="cvss" title="CVSS" sources={cve.field_sources.cvss_metrics}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          The headline score is NVD&apos;s own analysis when it has one, otherwise the score from the
          CVE&apos;s assigning organisation (CNA). All reported scores are listed below.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[32rem] text-left text-sm">
            <caption className="sr-only">CVSS scores by version and scorer</caption>
            <thead className="text-muted-foreground">
              <tr>
                <th className="py-1 pr-4 font-medium">Version</th>
                <th className="py-1 pr-4 font-medium">Score</th>
                <th className="py-1 pr-4 font-medium">Vector</th>
                <th className="py-1 font-medium">Reported by</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {cve.cvss_metrics.map((metric, index) => (
                <tr key={`${metric.source}-${metric.version}-${metric.scored_by}-${index}`}>
                  <td className="py-2 pr-4 font-mono">
                    CVSS {metric.version}
                    {isHeadline(metric, headline) && (
                      <Badge className="ml-2" data-testid="headline-badge">
                        Headline
                      </Badge>
                    )}
                  </td>
                  <td className="py-2 pr-4">
                    <SeverityBadge severity={metric.severity} score={metric.score} />
                  </td>
                  <td className="py-2 pr-4 font-mono text-xs break-all">{metric.vector ?? "—"}</td>
                  <td className="py-2">
                    {describeScorer(metric)}
                    <span className="block text-xs text-muted-foreground">
                      Source: {providerLabel(metric.source)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </SectionCard>
  );
}
