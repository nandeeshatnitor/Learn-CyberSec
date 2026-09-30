import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { AffectedSoftwareSection, AffectedVersionsSection } from "@/components/cve/affected-section";
import { CveErrorView } from "@/components/cve/cve-error-view";
import { CvssSection } from "@/components/cve/cvss-section";
import { KevSection } from "@/components/cve/kev-section";
import { ProviderStatusBanner } from "@/components/cve/provider-status-banner";
import { ReferencesSection } from "@/components/cve/references-section";
import { SourcesSection } from "@/components/cve/sources-section";
import { GenerateGuidePanel } from "@/components/research/generate-guide-panel";
import { WeaknessSection } from "@/components/cve/weakness-section";
import { DataOriginBanner } from "@/components/data-origin-banner";
import { SectionCard, UnavailableNotice } from "@/components/section-card";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { getCve } from "@/lib/api";
import { parseCveIdParam } from "@/lib/cve";
import { formatDate, providerLabel } from "@/lib/format";
import type { CveDetail } from "@/lib/types";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ cveId: string }> };

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  const cveId = parseCveIdParam((await params).cveId);
  return { title: cveId ?? "CVE not found" };
}

export default async function CvePage({ params }: Params) {
  const cveId = parseCveIdParam((await params).cveId);
  if (!cveId) notFound();

  const result = await getCve(cveId);
  if (!result.ok) return <CveErrorView cveId={cveId} error={result} />;
  const cve = result.data;

  return (
    <article className="space-y-6">
      <header className="space-y-3">
        <Link href="/" className="text-sm text-muted-foreground hover:text-foreground">
          ← Back to search
        </Link>
        <h1 className="font-mono text-3xl font-bold tracking-tight">{cve.cve_id}</h1>
        <div className="flex flex-wrap items-center gap-3">
          {cve.cvss && <SeverityBadge severity={cve.severity} score={cve.cvss.score} />}
          {cve.known_exploited === true && <Badge variant="destructive">Known exploited (KEV)</Badge>}
          {formatDate(cve.published_at) && (
            <span className="text-sm text-muted-foreground">Published {formatDate(cve.published_at)}</span>
          )}
        </div>
        <p className="text-sm text-muted-foreground">
          Information below was retrieved from public sources and is attributed to them. It has not
          been independently verified by this platform.
        </p>
      </header>

      <ProviderStatusBanner meta={cve.meta} />
      <DataOriginBanner origin={cve.data_origin} />

      <Overview cve={cve} />
      <SeveritySection cve={cve} />
      <CvssSection cve={cve} />
      <AffectedSoftwareSection cve={cve} />
      <AffectedVersionsSection cve={cve} />
      <WeaknessSection cve={cve} />
      <KevSection cve={cve} />
      <ReferencesSection cve={cve} />
      <SourcesSection cve={cve} />

      {/* Generated on demand from public sources; see components/research. */}
      <GenerateGuidePanel cveId={cve.cve_id} />
      <SectionCard id="hints" title="Hints" unavailable>
        <UnavailableNotice>Not available yet. Interactive hints are planned for a later phase.</UnavailableNotice>
      </SectionCard>
    </article>
  );
}

function Overview({ cve }: { cve: CveDetail }) {
  if (!cve.description) {
    return (
      <SectionCard id="overview" title="Overview" unavailable>
        <UnavailableNotice>
          No description was available from the sources that responded.
        </UnavailableNotice>
      </SectionCard>
    );
  }
  const facts: [string, string | null, string[] | undefined][] = [
    ["Status", cve.vuln_status, cve.field_sources.vuln_status],
    ["Published", formatDate(cve.published_at), cve.field_sources.published_at],
    ["Last modified", formatDate(cve.modified_at), cve.field_sources.modified_at],
  ];
  return (
    <SectionCard id="overview" title="Overview" sources={cve.field_sources.description}>
      {/* Plain text: React escapes it. External content is never injected as HTML. */}
      <p className="whitespace-pre-line leading-relaxed">{cve.description}</p>
      <dl className="mt-4 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
        {facts
          .filter(([, value]) => value)
          .map(([label, value, sources]) => (
            <div key={label}>
              <dt className="text-muted-foreground">{label}</dt>
              <dd>
                {value}
                {sources && sources.length > 0 && (
                  <span className="block text-xs text-muted-foreground">
                    per {sources.map(providerLabel).join(", ")}
                  </span>
                )}
              </dd>
            </div>
          ))}
      </dl>
    </SectionCard>
  );
}

function SeveritySection({ cve }: { cve: CveDetail }) {
  if (!cve.cvss) {
    return (
      <SectionCard id="severity" title="Severity" unavailable>
        <UnavailableNotice>No severity rating was reported by the available sources.</UnavailableNotice>
      </SectionCard>
    );
  }
  return (
    <SectionCard id="severity" title="Severity" sources={cve.field_sources.severity}>
      <div className="flex flex-wrap items-center gap-3">
        <SeverityBadge severity={cve.severity} score={cve.cvss.score} />
        <span className="text-sm text-muted-foreground">
          Based on CVSS {cve.cvss.version}. See the CVSS section for every reported score.
        </span>
      </div>
    </SectionCard>
  );
}
