import { CloudOff, Info } from "lucide-react";

import { formatDateTime } from "@/lib/format";
import type { ResponseMeta } from "@/lib/types";

/**
 * Explains, in plain words, when what is shown is incomplete or old: a provider was down,
 * a cached copy was served, or results come from a limited fallback.
 */
export function ProviderStatusBanner({ meta }: { meta: ResponseMeta }) {
  const problems = meta.providers.filter((p) =>
    ["stale", "unavailable", "rate_limited", "circuit_open"].includes(p.status),
  );
  if (problems.length === 0 && meta.warnings.length === 0 && meta.served_from === "providers") {
    return null;
  }
  const degraded = problems.length > 0 || meta.served_from !== "providers";

  return (
    <div
      role="status"
      data-testid="provider-status"
      className="space-y-2 rounded-lg border border-warning/40 bg-warning/10 p-4 text-sm"
    >
      <p className="flex items-center gap-2 font-medium">
        {degraded ? (
          <CloudOff aria-hidden className="size-4 text-warning" />
        ) : (
          <Info aria-hidden className="size-4 text-warning" />
        )}
        {degraded ? "Some sources are unavailable, so this page may be incomplete or out of date." : "Notes"}
      </p>
      <ul className="list-disc space-y-1 pl-6 text-muted-foreground">
        {meta.warnings.map((warning) => (
          <li key={warning}>{warning}</li>
        ))}
        {problems.map((p) => (
          <li key={p.provider}>
            {p.name}:{" "}
            {p.status === "stale"
              ? `showing a copy retrieved ${formatDateTime(p.retrieved_at) ?? "earlier"}`
              : (p.message ?? p.status.replace("_", " "))}
          </li>
        ))}
      </ul>
    </div>
  );
}
