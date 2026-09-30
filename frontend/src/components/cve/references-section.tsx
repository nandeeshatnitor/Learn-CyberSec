import { SafeLink } from "@/components/safe-link";
import { SectionCard, UnavailableNotice } from "@/components/section-card";
import { Badge } from "@/components/ui/badge";
import { hostnameOf, providerLabel } from "@/lib/format";
import type { CveRecord } from "@/lib/types";

export function ReferencesSection({ cve }: { cve: CveRecord }) {
  if (cve.references.length === 0) {
    return (
      <SectionCard id="references" title="References" unavailable>
        <UnavailableNotice>No references were listed by the available sources.</UnavailableNotice>
      </SectionCard>
    );
  }
  return (
    <SectionCard id="references" title="References" sources={cve.field_sources.references}>
      <p className="mb-3 text-sm text-muted-foreground">
        Links are shown exactly as the sources published them. They have not been visited or checked
        by this platform, so treat them as untrusted.
      </p>
      <ul className="divide-y">
        {cve.references.map((ref) => (
          <li key={ref.url} className="flex flex-col gap-1 py-3 first:pt-0 last:pb-0">
            <span className="break-all">
              <SafeLink href={ref.url}>{ref.title ?? ref.url}</SafeLink>
            </span>
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              {hostnameOf(ref.url) && <span className="font-mono">{hostnameOf(ref.url)}</span>}
              <span>Listed by {ref.sources.map(providerLabel).join(", ")}</span>
              {ref.tags.map((tag) => (
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
