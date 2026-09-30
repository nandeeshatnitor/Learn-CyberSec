import { SafeLink } from "@/components/safe-link";
import { SectionCard, UnavailableNotice } from "@/components/section-card";
import { SourceBadges } from "@/components/cve/source-badges";
import { cweUrl } from "@/lib/cve";
import type { CveRecord } from "@/lib/types";

const PLACEHOLDER_NOTE: Record<string, string> = {
  "NVD-CWE-Other": "NVD placeholder: a weakness that is not in the standard CWE list.",
  "NVD-CWE-noinfo": "NVD placeholder: not enough information to assign a CWE.",
};

export function WeaknessSection({ cve }: { cve: CveRecord }) {
  if (cve.cwes.length === 0) {
    return (
      <SectionCard id="cwe" title="Weakness (CWE)" unavailable>
        <UnavailableNotice>No CWE classification was reported by the available sources.</UnavailableNotice>
      </SectionCard>
    );
  }
  return (
    <SectionCard id="cwe" title="Weakness (CWE)" sources={cve.field_sources.cwes}>
      <ul className="space-y-3">
        {cve.cwes.map((cwe) => (
          <li key={cwe.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="font-mono font-medium">
              <SafeLink href={cweUrl(cwe.id)}>{cwe.id}</SafeLink>
            </span>
            {(cwe.name || PLACEHOLDER_NOTE[cwe.id]) && (
              <span className="text-sm text-muted-foreground">
                {cwe.name ?? PLACEHOLDER_NOTE[cwe.id]}
              </span>
            )}
            <SourceBadges sources={cwe.sources} />
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}
