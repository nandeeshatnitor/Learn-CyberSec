import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { CveSearchForm } from "@/components/cve-search-form";
import { SeverityBadge } from "@/components/severity-badge";
import { Card } from "@/components/ui/card";
import { searchCves } from "@/lib/api";
import { normalizeCveId, sanitizeQuery } from "@/lib/cve";

export const metadata: Metadata = { title: "Search results" };
export const dynamic = "force-dynamic";

export default async function SearchPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string | string[] }>;
}) {
  const { q } = await searchParams;
  const query = sanitizeQuery(Array.isArray(q) ? q[0] : q);

  // A well-formed CVE ID goes straight to its page (which explains if it isn't available yet).
  const cveId = normalizeCveId(query);
  if (cveId) redirect(`/cves/${cveId}`);

  const result = query ? await searchCves(query) : null;

  return (
    <div className="space-y-8">
      <div className="space-y-4">
        <h1 className="text-3xl font-bold tracking-tight">Search</h1>
        <CveSearchForm defaultValue={query} />
      </div>

      {!query && (
        <p className="text-muted-foreground">Enter a CVE ID or a keyword to search.</p>
      )}

      {result && !result.ok && (
        <Card className="p-5" role="alert">
          {result.kind === "unavailable"
            ? "The search service is unavailable right now. Please try again shortly."
            : "That search could not be processed. Try a different query."}
        </Card>
      )}

      {result?.ok && (
        <section aria-live="polite" className="space-y-4">
          <p className="text-sm text-muted-foreground">
            {result.data.total} result{result.data.total === 1 ? "" : "s"} in the local database
            for <span className="font-mono text-foreground">{result.data.query}</span>
          </p>
          {result.data.total === 0 ? (
            <Card className="border-dashed bg-transparent p-5 text-muted-foreground">
              Nothing matched. Retrieval from public sources (NVD, MITRE, vendor advisories, …) is
              not implemented yet, so only locally stored records can be found.
            </Card>
          ) : (
            <ul className="space-y-3">
              {result.data.items.map((item) => (
                <li key={item.id}>
                  <Link
                    href={`/cves/${item.cve_id}`}
                    className="block rounded-lg border bg-card p-4 transition-colors hover:border-primary/60"
                  >
                    <div className="flex flex-wrap items-center gap-3">
                      <span className="font-mono font-medium text-primary">{item.cve_id}</span>
                      <SeverityBadge severity={item.severity} score={item.cvss_score} />
                    </div>
                    <p className="mt-2 line-clamp-2 text-sm text-muted-foreground">
                      {item.description}
                    </p>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}
