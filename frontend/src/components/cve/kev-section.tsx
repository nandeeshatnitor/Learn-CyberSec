import { SectionCard } from "@/components/section-card";
import { Badge } from "@/components/ui/badge";
import { formatDate, formatDateTime, providerLabel } from "@/lib/format";
import type { CveRecord } from "@/lib/types";

/** Known exploitation status, with three honest states: listed, not listed, unknown. */
export function KevSection({ cve }: { cve: CveRecord }) {
  const { known_exploited: known, kev } = cve;
  const sources = cve.field_sources.known_exploited;

  if (known === null) {
    return (
      <SectionCard id="exploitation" title="Known exploitation status" unavailable>
        <p className="text-sm text-muted-foreground">
          <strong className="text-foreground">Unknown.</strong> The CISA Known Exploited
          Vulnerabilities (KEV) catalogue could not be consulted, so this page cannot say whether
          this CVE is listed. This is not the same as &ldquo;not exploited&rdquo;.
        </p>
      </SectionCard>
    );
  }

  if (!known || !kev) {
    const checked = cve.sources.find((s) => s.provider === "cisa_kev")?.retrieved_at ?? cve.retrieved_at;
    return (
      <SectionCard id="exploitation" title="Known exploitation status" sources={sources}>
        <div className="space-y-2 text-sm">
          <Badge variant="muted">Not in the CISA KEV catalogue</Badge>
          <p className="text-muted-foreground">
            Not listed in CISA&apos;s KEV catalogue{formatDateTime(checked) ? ` as of ${formatDateTime(checked)}` : ""}.
            That does not mean the vulnerability is not being exploited: KEV only lists exploitation
            CISA has evidence of.
          </p>
        </div>
      </SectionCard>
    );
  }

  const facts: [string, string | null][] = [
    ["Name", kev.vulnerability_name],
    ["Date added to catalogue", formatDate(kev.date_added)],
    ["Remediation due date (US federal agencies)", formatDate(kev.due_date)],
    ["Known ransomware campaign use", kev.known_ransomware_campaign_use],
  ];
  return (
    <SectionCard id="exploitation" title="Known exploitation status" sources={sources}>
      <div className="space-y-3 text-sm">
        <Badge variant="destructive">Listed in the CISA KEV catalogue</Badge>
        {kev.source !== "cisa_kev" && (
          <p className="text-muted-foreground">
            Reported by {providerLabel(kev.source)} (its copy of CISA&apos;s data); the CISA catalogue
            itself could not be consulted.
          </p>
        )}
        {kev.short_description && <p>{kev.short_description}</p>}
        <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
          {facts
            .filter(([, value]) => value)
            .map(([label, value]) => (
              <div key={label}>
                <dt className="text-muted-foreground">{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
        </dl>
        {kev.required_action && (
          <div>
            <p className="text-muted-foreground">Required action (as published by CISA)</p>
            <p>{kev.required_action}</p>
          </div>
        )}
        {kev.notes && (
          <div>
            <p className="text-muted-foreground">Notes</p>
            <p className="break-words">{kev.notes}</p>
          </div>
        )}
      </div>
    </SectionCard>
  );
}
