import { TriangleAlert } from "lucide-react";

import type { CveRecord } from "@/lib/types";

/** Tells the reader when a record is a development fixture rather than retrieved data. */
export function DataOriginBanner({ origin }: { origin: CveRecord["data_origin"] }) {
  if (origin !== "seed") return null;
  return (
    <div
      role="note"
      className="flex items-start gap-3 rounded-lg border border-warning/40 bg-warning/10 p-4 text-sm"
    >
      <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-warning" />
      <p>
        <strong>Development sample record.</strong> This entry was entered by hand for testing and
        was <em>not</em> retrieved from NVD or any other public source. Verify every detail against
        the original sources before relying on it.
      </p>
    </div>
  );
}
