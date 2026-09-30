import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { LearningWorkspace } from "@/components/learn/learning-workspace";
import { SeverityBadge } from "@/components/severity-badge";
import { getCve } from "@/lib/api";
import { parseCveIdParam } from "@/lib/cve";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ cveId: string }> };

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  const cveId = parseCveIdParam((await params).cveId);
  return { title: cveId ? `Learn ${cveId}` : "CVE not found" };
}

export default async function LearnPage({ params }: Params) {
  const cveId = parseCveIdParam((await params).cveId);
  if (!cveId) notFound();
  const cve = await getCve(cveId); // for the header only: the workspace loads its own data

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <Link href={`/cves/${cveId}`} className="text-sm text-muted-foreground hover:text-foreground">
          ← Back to {cveId}
        </Link>
        <h1 className="font-mono text-3xl font-bold tracking-tight">
          <span className="sr-only">Learn </span>
          {cveId}
        </h1>
        {cve.ok && cve.data.cvss && (
          <SeverityBadge severity={cve.data.severity} score={cve.data.cvss.score} />
        )}
        <p className="text-sm text-muted-foreground">
          An interactive lesson built from public sources. For education and authorized testing only.
        </p>
      </header>
      <LearningWorkspace cveId={cveId} />
    </div>
  );
}
