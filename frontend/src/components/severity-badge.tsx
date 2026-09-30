import { Badge } from "@/components/ui/badge";

const VARIANT = {
  CRITICAL: "destructive",
  HIGH: "destructive",
  MEDIUM: "warning",
  LOW: "muted",
} as const;

export function SeverityBadge({ severity, score }: { severity: string | null; score?: number | null }) {
  if (!severity && score == null) return <Badge variant="outline">Severity unavailable</Badge>;
  const key = (severity ?? "").toUpperCase() as keyof typeof VARIANT;
  return (
    <Badge variant={VARIANT[key] ?? "outline"}>
      {score != null && <span className="mr-1 font-mono">{score.toFixed(1)}</span>}
      {severity ?? ""}
    </Badge>
  );
}
