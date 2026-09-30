import { sanitizeQuery } from "@/lib/cve";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
export const MAX_PAGE = 1000;

export interface SearchParams {
  q: string;
  page: number;
  severity?: (typeof SEVERITIES)[number];
  knownExploited: boolean;
}

type Raw = Record<string, string | string[] | undefined>;

const first = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value);

/** Validate untrusted query-string values; anything unexpected falls back to a safe default. */
export function parseSearchParams(raw: Raw): SearchParams {
  const page = Number.parseInt(first(raw.page) ?? "1", 10);
  const severity = (first(raw.severity) ?? "").toUpperCase();
  return {
    q: sanitizeQuery(first(raw.q)),
    page: Number.isInteger(page) && page >= 1 ? Math.min(page, MAX_PAGE) : 1,
    severity: SEVERITIES.find((s) => s === severity),
    knownExploited: first(raw.known_exploited) === "true",
  };
}

/** Build /cves?... for links (pagination), omitting defaults. */
export function buildSearchHref(params: Partial<SearchParams> & { q: string }): string {
  const search = new URLSearchParams({ q: params.q });
  if (params.page && params.page > 1) search.set("page", String(params.page));
  if (params.severity) search.set("severity", params.severity);
  if (params.knownExploited) search.set("known_exploited", "true");
  return `/cves?${search}`;
}
