import Link from "next/link";

import { SourceBadges } from "@/components/cve/source-badges";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { formatDate, productName } from "@/lib/format";
import type { CveRecord } from "@/lib/types";

function KevBadge({ known }: { known: boolean | null }) {
  if (known === true) return <Badge variant="destructive">Known exploited (KEV)</Badge>;
  if (known === null) return <Badge variant="outline">KEV status unknown</Badge>;
  return null;
}

export function SearchResultList({ items }: { items: CveRecord[] }) {
  return (
    <ul className="space-y-3" data-testid="results">
      {items.map((item) => {
        const products = [...new Set(item.affected_products.map(productName))];
        return (
          <li key={item.cve_id}>
            <Link
              href={`/cves/${item.cve_id}`}
              className="block rounded-lg border bg-card p-4 transition-colors hover:border-primary/60"
            >
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-mono font-medium text-primary">{item.cve_id}</span>
                {item.cvss && <SeverityBadge severity={item.severity} score={item.cvss.score} />}
                <KevBadge known={item.known_exploited} />
                {formatDate(item.published_at) && (
                  <span className="text-xs text-muted-foreground">
                    Published {formatDate(item.published_at)}
                  </span>
                )}
              </div>
              <p className="mt-2 line-clamp-2 text-sm text-muted-foreground">
                {item.description ?? "No description was available from the retrieved sources."}
              </p>
              {products.length > 0 && (
                <p className="mt-2 text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">Affects:</span>{" "}
                  {products.slice(0, 3).join(", ")}
                  {products.length > 3 ? ` +${products.length - 3} more` : ""}
                </p>
              )}
              <div className="mt-2">
                <SourceBadges sources={item.sources.map((s) => s.provider)} />
              </div>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
