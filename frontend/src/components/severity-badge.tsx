import { Badge } from "@/components/ui/badge";
import { severityVariant } from "@/lib/format";

export function SeverityBadge({
  severity,
  score,
}: {
  severity: string | null;
  score?: number | null;
}) {
  if (!severity && score == null) return <Badge variant="outline">Severity unavailable</Badge>;
  return (
    <Badge variant={severityVariant(severity)}>
      {score != null && <span className="mr-1 font-mono">{score.toFixed(1)}</span>}
      {severity ?? ""}
    </Badge>
  );
}
