import { LoadingSkeleton } from "@/components/loading-skeleton";

export default function Loading() {
  return <LoadingSkeleton rows={4} label="Preparing the lesson…" />;
}
