import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { CveSearchForm } from "@/components/cve-search-form";
import { ProviderStatusBanner } from "@/components/cve/provider-status-banner";
import { SearchResultList } from "@/components/cve/search-result-list";
import { SearchEmptyState, SearchErrorState, SearchPrompt } from "@/components/cve/search-states";
import { Pagination } from "@/components/pagination";
import { searchCves } from "@/lib/api";
import { normalizeCveId } from "@/lib/cve";
import { buildSearchHref, parseSearchParams } from "@/lib/search-params";

export const metadata: Metadata = { title: "Search results" };
export const dynamic = "force-dynamic";

const QUERY_NOTES = {
  cve_id: null,
  partial_cve_id:
    "Partial CVE IDs only match CVEs this platform has already retrieved and the CISA KEV catalogue.",
  keyword: null,
} as const;

export default async function SearchPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = parseSearchParams(await searchParams);

  // A well-formed CVE ID goes straight to its page, which explains if it cannot be found.
  const cveId = normalizeCveId(params.q);
  if (cveId && !params.severity && !params.knownExploited) redirect(`/cves/${cveId}`);

  const result = params.q
    ? await searchCves(params.q, {
        page: params.page,
        severity: params.severity,
        knownExploited: params.knownExploited,
      })
    : null;

  return (
    <div className="space-y-8">
      <div className="space-y-4">
        <h1 className="text-3xl font-bold tracking-tight">Search</h1>
        <CveSearchForm
          defaultValue={params.q}
          showFilters
          severity={params.severity}
          knownExploited={params.knownExploited}
        />
      </div>

      {!result && <SearchPrompt />}
      {result && !result.ok && <SearchErrorState error={result} />}

      {result?.ok && (
        <section aria-live="polite" className="space-y-4" data-testid="search-results">
          <p className="text-sm text-muted-foreground">
            {result.data.total.toLocaleString("en-US")} result{result.data.total === 1 ? "" : "s"} for{" "}
            <span className="font-mono text-foreground">{result.data.query}</span>
            {(params.severity || params.knownExploited) && " (filtered)"}
          </p>
          <ProviderStatusBanner meta={result.data.meta} />
          {QUERY_NOTES[result.data.query_type] && (
            <p className="text-sm text-muted-foreground">{QUERY_NOTES[result.data.query_type]}</p>
          )}
          {result.data.items.length === 0 ? (
            <SearchEmptyState
              query={result.data.query}
              filtered={Boolean(params.severity || params.knownExploited)}
            />
          ) : (
            <>
              <SearchResultList items={result.data.items} />
              <Pagination
                page={result.data.page}
                pages={result.data.pages}
                hrefFor={(page) => buildSearchHref({ ...params, page })}
              />
            </>
          )}
        </section>
      )}
    </div>
  );
}
