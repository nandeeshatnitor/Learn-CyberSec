import { Badge } from "@/components/ui/badge";
import { providerLabel } from "@/lib/format";

/** "Source: NVD" pills. Says where data came from; never that it was verified here. */
export function SourceBadges({ sources }: { sources?: string[] }) {
  if (!sources || sources.length === 0) return null;
  return (
    <span className="flex flex-wrap items-center gap-1.5" data-testid="source-badges">
      {sources.map((source) => (
        <Badge key={source} variant="muted">
          Source: {providerLabel(source)}
        </Badge>
      ))}
    </span>
  );
}
