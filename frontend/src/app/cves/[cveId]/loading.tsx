import { LoadingSkeleton } from "@/components/loading-skeleton";

export default function Loading() {
  return <LoadingSkeleton rows={6} label="Retrieving vulnerability information…" />;
}
