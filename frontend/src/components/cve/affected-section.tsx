import { SectionCard, UnavailableNotice } from "@/components/section-card";
import { Badge } from "@/components/ui/badge";
import { formatVersionRange, productName, providerLabel } from "@/lib/format";
import type { AffectedProduct, CveRecord } from "@/lib/types";

function groupBySource(products: AffectedProduct[]): [string, AffectedProduct[]][] {
  const groups = new Map<string, AffectedProduct[]>();
  for (const product of products) {
    groups.set(product.source, [...(groups.get(product.source) ?? []), product]);
  }
  return [...groups.entries()];
}

const NOT_REPORTED = "No affected software was reported by the available sources.";

/**
 * Statements from different sources are shown separately, never blended: NVD describes
 * software by CPE configuration, the CNA by its own product/version list.
 */
export function AffectedSoftwareSection({ cve }: { cve: CveRecord }) {
  if (cve.affected_products.length === 0) {
    return (
      <SectionCard id="affected-software" title="Affected software" unavailable>
        <UnavailableNotice>{NOT_REPORTED}</UnavailableNotice>
      </SectionCard>
    );
  }
  return (
    <SectionCard
      id="affected-software"
      title="Affected software"
      sources={cve.field_sources.affected_products}
    >
      <div className="space-y-4">
        {groupBySource(cve.affected_products).map(([source, products]) => (
          <div key={source}>
            <h3 className="mb-2 text-sm font-medium text-muted-foreground">
              Reported by {providerLabel(source)}
            </h3>
            <ul className="flex flex-wrap gap-2">
              {products.map((product, index) => (
                <li key={`${product.vendor}-${product.product}-${index}`}>
                  <Badge variant="outline" className="text-sm">
                    {productName(product)}
                  </Badge>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}

export function AffectedVersionsSection({ cve }: { cve: CveRecord }) {
  const withVersions = cve.affected_products.filter((p) => p.versions.length > 0);
  if (withVersions.length === 0) {
    return (
      <SectionCard id="affected-versions" title="Affected versions" unavailable>
        <UnavailableNotice>
          No version information was reported by the available sources.
        </UnavailableNotice>
      </SectionCard>
    );
  }
  return (
    <SectionCard
      id="affected-versions"
      title="Affected versions"
      sources={[...new Set(withVersions.map((p) => p.source))]}
    >
      <div className="space-y-5">
        {groupBySource(withVersions).map(([source, products]) => (
          <div key={source}>
            <h3 className="mb-2 text-sm font-medium text-muted-foreground">
              Reported by {providerLabel(source)}
            </h3>
            <ul className="space-y-3">
              {products.map((product, index) => (
                <li key={`${product.vendor}-${product.product}-${index}`}>
                  <p className="font-medium">{productName(product)}</p>
                  <ul className="mt-1 space-y-0.5 font-mono text-sm text-muted-foreground">
                    {product.versions.map((range, i) => (
                      <li key={i}>{formatVersionRange(range)}</li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}
