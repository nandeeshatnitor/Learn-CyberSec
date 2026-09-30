import { CircleAlert, SearchX } from "lucide-react";

import { Card } from "@/components/ui/card";
import type { ApiError } from "@/lib/api-types";

export function SearchPrompt() {
  return (
    <p className="text-muted-foreground">
      Search by CVE ID (<code className="font-mono">CVE-2024-1234</code>), part of an ID, a keyword
      (<em>remote code execution</em>), or a product or vendor name (<em>openssl</em>,{" "}
      <em>apache</em>).
    </p>
  );
}

export function SearchEmptyState({ query, filtered }: { query: string; filtered: boolean }) {
  return (
    <Card className="border-dashed bg-transparent p-5" data-testid="empty-state">
      <p className="flex items-start gap-2 text-muted-foreground">
        <SearchX aria-hidden className="mt-0.5 size-5 shrink-0" />
        <span>
          No CVEs matched <span className="font-mono text-foreground">{query}</span>
          {filtered ? " with the selected filters. Try removing a filter." : "."} Try a different
          spelling, a broader keyword, or a full CVE ID.
        </span>
      </p>
    </Card>
  );
}

const MESSAGES: Record<ApiError["kind"], string> = {
  unavailable:
    "The search service is unavailable right now. Please try again shortly. Nothing was lost.",
  rate_limited: "You are searching too quickly. Please wait a moment and try again.",
  invalid: "That search could not be processed. Try a different query.",
  not_found: "That search could not be processed. Try a different query.",
};

export function SearchErrorState({ error }: { error: ApiError }) {
  return (
    <Card className="border-destructive/40 p-5" role="alert" data-testid="error-state">
      <p className="flex items-start gap-2">
        <CircleAlert aria-hidden className="mt-0.5 size-5 shrink-0 text-destructive" />
        <span>
          {MESSAGES[error.kind]}
          {error.kind === "rate_limited" && error.retryAfter
            ? ` (retry in about ${Math.ceil(error.retryAfter)} seconds)`
            : ""}
        </span>
      </p>
    </Card>
  );
}
