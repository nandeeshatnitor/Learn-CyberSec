import { Badge } from "@/components/ui/badge";
import { STATUS_LABELS, type CandidateStatusName, type StageName } from "@/lib/admin-types";

type Variant = "default" | "muted" | "outline" | "warning" | "destructive";

const STATUS_VARIANT: Record<CandidateStatusName, Variant> = {
  generating: "muted",
  generation_failed: "destructive",
  spec_only: "outline",
  building: "muted",
  build_failed: "destructive",
  validating: "muted",
  validation_failed: "destructive",
  awaiting_review: "warning",
  changes_requested: "warning",
  rejected: "destructive",
  approved: "default",
};

export function StatusBadge({ status }: { status: CandidateStatusName }) {
  return (
    <Badge variant={STATUS_VARIANT[status] ?? "outline"} data-testid="status-badge">
      {STATUS_LABELS[status] ?? status}
    </Badge>
  );
}

const STAGE_LABEL: Record<StageName, string> = {
  pending: "Pending",
  running: "Running",
  passed: "Passed",
  failed: "Failed",
  skipped: "Skipped",
};
const STAGE_VARIANT: Record<StageName, Variant> = {
  pending: "outline",
  running: "muted",
  passed: "default",
  failed: "destructive",
  skipped: "outline",
};

export function StageBadge({ stage }: { stage: StageName }) {
  return <Badge variant={STAGE_VARIANT[stage] ?? "outline"}>{STAGE_LABEL[stage] ?? stage}</Badge>;
}
