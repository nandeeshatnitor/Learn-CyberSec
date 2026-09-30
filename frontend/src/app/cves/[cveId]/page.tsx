import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { DataOriginBanner } from "@/components/data-origin-banner";
import { SafeLink } from "@/components/safe-link";
import { SectionCard, UnavailableNotice } from "@/components/section-card";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { getCve } from "@/lib/api";
import { cweUrl, parseCveIdParam } from "@/lib/cve";
import type { Cve } from "@/lib/types";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ cveId: string }> };

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  const cveId = parseCveIdParam((await params).cveId);
  return { title: cveId ?? "CVE not found" };
}

const formatDate = (iso: string | null) =>
  iso ? new Date(iso).toLocaleDateString("en-CA", { timeZone: "UTC" }) : null;

export default async function CvePage({ params }: Params) {
  const cveId = parseCveIdParam((await params).cveId);
  if (!cveId) notFound();

  const result = await getCve(cveId);
  const cve = result.ok ? result.data : null;

  return (
    <article className="space-y-6">
      <header className="space-y-3">
        <Link href="/" className="text-sm text-muted-foreground hover:text-foreground">
          ← Back to search
        </Link>
        <h1 className="font-mono text-3xl font-bold tracking-tight">{cveId}</h1>
        {cve && (
          <div className="flex flex-wrap items-center gap-3">
            <SeverityBadge severity={cve.severity} score={cve.cvss_score} />
            {formatDate(cve.published_at) && (
              <span className="text-sm text-muted-foreground">
                Published {formatDate(cve.published_at)}
              </span>
            )}
          </div>
        )}
      </header>

      {!result.ok && (
        <div role="status" className="rounded-lg border border-dashed p-4 text-sm">
          {result.kind === "not_found" ? (
            <>
              <strong>{cveId} is not in the local database.</strong> Retrieval from public sources
              is not implemented yet, so no information is shown below rather than guessing.
            </>
          ) : (
            <>
              <strong>The API is unavailable</strong>, so this CVE could not be loaded. Please try
              again shortly.
            </>
          )}
        </div>
      )}

      {cve && <DataOriginBanner origin={cve.data_origin} />}

      <Overview cve={cve} />
      <AffectedVersions cve={cve} />
      <Severity cve={cve} />
      <Weakness cve={cve} />
      <References cve={cve} />

      <SectionCard id="learning-guide" title="Learning Guide" availability="unavailable">
        <UnavailableNotice>
          Not available yet. A structured walkthrough (what it is, why it happens, how it works)
          will be built from cited sources in a later phase.
        </UnavailableNotice>
      </SectionCard>
      <SectionCard id="reproduction" title="Reproduction" availability="unavailable">
        <UnavailableNotice>
          Not available yet. Reproduction steps, prerequisites and success evidence for an
          authorised local lab will come with the sandbox phase. Nothing is executed
          automatically.
        </UnavailableNotice>
      </SectionCard>
      <SectionCard id="hints" title="Hints" availability="unavailable">
        <UnavailableNotice>Not available yet. Interactive hints are planned for a later phase.</UnavailableNotice>
      </SectionCard>
      <SectionCard id="remediation" title="Remediation" availability="unavailable">
        <UnavailableNotice>
          Not available yet. For fixes today, follow the vendor advisories linked under
          References once they are available.
        </UnavailableNotice>
      </SectionCard>
    </article>
  );
}

function Overview({ cve }: { cve: Cve | null }) {
  if (!cve) {
    return (
      <SectionCard id="overview" title="Overview" availability="unavailable">
        <UnavailableNotice>No description is available for this CVE yet.</UnavailableNotice>
      </SectionCard>
    );
  }
  return (
    <SectionCard id="overview" title="Overview" availability="available">
      {/* Rendered as text: React escapes it, and external content is never injected as HTML. */}
      <p className="whitespace-pre-line leading-relaxed">{cve.description}</p>
    </SectionCard>
  );
}

function AffectedVersions({ cve }: { cve: Cve | null }) {
  if (!cve || cve.affected_products.length === 0) {
    return (
      <SectionCard id="affected-versions" title="Affected Versions" availability="unavailable">
        <UnavailableNotice>No affected product or version data is available.</UnavailableNotice>
      </SectionCard>
    );
  }
  return (
    <SectionCard id="affected-versions" title="Affected Versions" availability="available">
      <ul className="space-y-2">
        {cve.affected_products.map((p, i) => (
          <li key={i} className="text-sm">
            <span className="font-medium">
              {[p.vendor, p.product].filter(Boolean).join(" ") || "Unnamed product"}
            </span>
            {p.versions && <span className="ml-2 font-mono text-muted-foreground">{p.versions}</span>}
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}

function Severity({ cve }: { cve: Cve | null }) {
  if (!cve || (cve.cvss_score == null && !cve.severity && !cve.cvss_vector)) {
    return (
      <SectionCard id="severity" title="Severity" availability="unavailable">
        <UnavailableNotice>No CVSS score or severity rating is available.</UnavailableNotice>
      </SectionCard>
    );
  }
  return (
    <SectionCard id="severity" title="Severity" availability="available">
      <div className="space-y-2 text-sm">
        <SeverityBadge severity={cve.severity} score={cve.cvss_score} />
        {cve.cvss_vector && (
          <p>
            <span className="text-muted-foreground">Vector: </span>
            <code className="break-all font-mono">{cve.cvss_vector}</code>
          </p>
        )}
      </div>
    </SectionCard>
  );
}

function Weakness({ cve }: { cve: Cve | null }) {
  if (!cve || cve.cwes.length === 0) {
    return (
      <SectionCard id="weakness" title="Weakness" availability="unavailable">
        <UnavailableNotice>No CWE classification is available.</UnavailableNotice>
      </SectionCard>
    );
  }
  return (
    <SectionCard id="weakness" title="Weakness" availability="available">
      <ul className="flex flex-wrap gap-2">
        {cve.cwes.map((cwe) => (
          <li key={cwe}>
            <Badge variant="outline" className="font-mono">
              <SafeLink href={cweUrl(cwe)}>{cwe}</SafeLink>
            </Badge>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}

function References({ cve }: { cve: Cve | null }) {
  if (!cve || cve.references.length === 0) {
    return (
      <SectionCard id="references" title="References" availability="unavailable">
        <UnavailableNotice>No sources are linked to this CVE yet.</UnavailableNotice>
      </SectionCard>
    );
  }
  return (
    <SectionCard id="references" title="References" availability="available">
      <ul className="divide-y">
        {cve.references.map(({ source, tags }) => (
          <li key={source.id} className="flex flex-col gap-1 py-3 first:pt-0 last:pb-0">
            <SafeLink href={source.url}>{source.title}</SafeLink>
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              {source.publisher && <span>{source.publisher}</span>}
              <Badge variant="muted">{source.source_type.replace("_", " ")}</Badge>
              <Badge variant="outline">reliability: {source.reliability_level}</Badge>
              <span>
                {source.retrieved_at
                  ? `retrieved ${formatDate(source.retrieved_at)}`
                  : "content not retrieved (link only)"}
              </span>
              {tags.map((tag) => (
                <Badge key={tag} variant="outline">
                  {tag}
                </Badge>
              ))}
            </div>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}
