import { CircleSlash2 } from "lucide-react";
import type { ReactNode } from "react";

import { SourceBadges } from "@/components/cve/source-badges";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * One section of the CVE page. Sections with data name the source(s) they came from
 * ("Source: NVD"); sections without data are visually distinct (dashed border, badge) so a
 * reader can never mistake a missing section for one that has content.
 */
export function SectionCard({
  id,
  title,
  sources,
  unavailable = false,
  children,
}: {
  id: string;
  title: string;
  /** Provider IDs that supplied this section's data. Ignored when unavailable. */
  sources?: string[];
  unavailable?: boolean;
  children: ReactNode;
}) {
  return (
    <section
      id={id}
      aria-labelledby={`${id}-title`}
      data-availability={unavailable ? "unavailable" : "available"}
    >
      <Card className={cn(unavailable && "border-dashed bg-transparent")}>
        <CardHeader className="flex-row flex-wrap items-center justify-between gap-3">
          <CardTitle id={`${id}-title`} className={cn(unavailable && "text-muted-foreground")}>
            {title}
          </CardTitle>
          {unavailable ? <Badge variant="outline">Not available</Badge> : <SourceBadges sources={sources} />}
        </CardHeader>
        <CardContent>{children}</CardContent>
      </Card>
    </section>
  );
}

export function UnavailableNotice({ children }: { children: ReactNode }) {
  return (
    <p className="flex items-start gap-2 text-sm text-muted-foreground">
      <CircleSlash2 aria-hidden className="mt-0.5 size-4 shrink-0" />
      <span>{children}</span>
    </p>
  );
}
