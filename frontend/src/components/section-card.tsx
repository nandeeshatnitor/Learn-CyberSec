import { CircleSlash2 } from "lucide-react";
import type { ReactNode } from "react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

type Availability = "available" | "unavailable";

/**
 * One section of the CVE page. "unavailable" sections are visually distinct (dashed border,
 * badge) so a reader can never mistake a missing section for one that has content.
 */
export function SectionCard({
  id,
  title,
  availability,
  children,
}: {
  id: string;
  title: string;
  availability: Availability;
  children: ReactNode;
}) {
  const unavailable = availability === "unavailable";
  return (
    <section id={id} aria-labelledby={`${id}-title`} data-availability={availability}>
      <Card className={cn(unavailable && "border-dashed bg-transparent")}>
        <CardHeader className="flex-row items-center justify-between gap-3">
          <CardTitle id={`${id}-title`} className={cn(unavailable && "text-muted-foreground")}>
            {title}
          </CardTitle>
          {unavailable ? (
            <Badge variant="outline">Not available</Badge>
          ) : (
            <Badge variant="muted">From local database</Badge>
          )}
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
