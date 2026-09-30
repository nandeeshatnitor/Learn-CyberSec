import { LoadingSkeleton } from "@/components/loading-skeleton";

export default function Loading() {
  return <LoadingSkeleton rows={5} label="Searching public vulnerability databases…" />;
}
