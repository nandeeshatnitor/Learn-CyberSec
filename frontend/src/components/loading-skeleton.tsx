import { cn } from "@/lib/utils";

/** Announced to screen readers; visual placeholder blocks while a server component loads. */
export function LoadingSkeleton({ rows = 4, label = "Loading…" }: { rows?: number; label?: string }) {
  return (
    <div role="status" aria-busy="true" className="space-y-4" data-testid="loading">
      <span className="sr-only">{label}</span>
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          aria-hidden
          className={cn("animate-pulse rounded-lg border bg-card", i === 0 ? "h-10 w-2/3" : "h-24")}
        />
      ))}
    </div>
  );
}
