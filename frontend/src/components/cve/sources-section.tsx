import { SafeLink } from "@/components/safe-link";
import { SectionCard } from "@/components/section-card";
import { Badge } from "@/components/ui/badge";
import { formatDateTime } from "@/lib/format";
import type { CveRecord } from "@/lib/types";

/** Where this page's data came from, and how fresh it is. The transparency statement lives here. */
export function SourcesSection({ cve }: { cve: CveRecord }) {
  return (
    <SectionCard id="sources" title="Sources and retrieval" sources={undefined}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          This platform <strong className="text-foreground">retrieves and displays</strong>{" "}
          information published by the sources below. It does <strong className="text-foreground">not</strong>{" "}
          independently verify it. Check the original source before relying on any detail.
        </p>
        {cve.sources.length === 0 ? (
          <p className="text-sm">No source retrieved this record.</p>
        ) : (
          <ul className="space-y-3">
            {cve.sources.map((source) => (
              <li key={source.provider} className="rounded-md border p-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{source.name}</span>
                  {source.stale && <Badge variant="warning">Older copy</Badge>}
                </div>
                <p className="text-muted-foreground">{source.publisher}</p>
                <p className="text-muted-foreground">
                  {source.stale ? "Last retrieved" : "Retrieved"} {formatDateTime(source.retrieved_at)}
                </p>
                {source.url && (
                  <p className="mt-1 break-all">
                    <SafeLink href={source.url}>View original at {source.name}</SafeLink>
                  </p>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </SectionCard>
  );
}
