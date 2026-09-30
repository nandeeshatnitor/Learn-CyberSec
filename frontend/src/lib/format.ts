import type { CvssMetric, Severity, VersionRange } from "@/lib/types";

/** Human names for provider IDs. Unknown IDs fall back to the ID itself (rendered as text). */
const PROVIDER_LABELS: Record<string, string> = {
  nvd: "NVD",
  mitre: "MITRE / CVE Program",
  cisa_kev: "CISA KEV",
  seed: "Sample data",
};

export function providerLabel(id: string): string {
  return PROVIDER_LABELS[id] ?? id;
}

/** "2021-12-10" (UTC). */
export function formatDate(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date.toISOString().slice(0, 10);
}

/** "2021-12-10 10:15 UTC". */
export function formatDateTime(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return `${date.toISOString().slice(0, 10)} ${date.toISOString().slice(11, 16)} UTC`;
}

/** e.g. "2.0.1 ≤ version < 2.3.1", "version ≤ 3.4", "2.15.0", "All versions". */
export function formatVersionRange(range: VersionRange): string {
  const lower = range.start_including
    ? `${range.start_including} ≤ version`
    : range.start_excluding
      ? `${range.start_excluding} < version`
      : null;
  const upper = range.end_excluding
    ? `< ${range.end_excluding}`
    : range.end_including
      ? `≤ ${range.end_including}`
      : null;

  let text: string;
  if (lower || upper) {
    text = lower && upper ? `${lower} ${upper}` : lower ? lower : `version ${upper}`;
  } else if (!range.version || range.version === "*") {
    text = "All versions";
  } else {
    text = range.version;
  }
  if (range.status === "unaffected") return `${text} (not affected)`;
  if (range.status === "unknown") return `${text} (status unknown)`;
  return text;
}

/** Who produced a CVSS score, without implying more than the source said. */
export function describeScorer(metric: CvssMetric): string {
  if (metric.source === "nvd" && metric.primary) return "NVD analysis";
  if (metric.scored_by && /^(CNA|ADP)\b/.test(metric.scored_by)) return metric.scored_by;
  return "Secondary source (as listed by " + providerLabel(metric.source) + ")";
}

export function severityVariant(severity: Severity | string | null | undefined) {
  switch ((severity ?? "").toUpperCase()) {
    case "CRITICAL":
    case "HIGH":
      return "destructive" as const;
    case "MEDIUM":
      return "warning" as const;
    case "LOW":
      return "muted" as const;
    default:
      return "outline" as const;
  }
}

/** Hostname of an http(s) URL for display next to a link, or null. */
export function hostnameOf(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

export function productName(product: { vendor: string | null; product: string | null }): string {
  return [product.vendor, product.product].filter(Boolean).join(" ") || "Unnamed product";
}
