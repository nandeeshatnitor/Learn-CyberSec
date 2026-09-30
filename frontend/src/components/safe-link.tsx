import { ExternalLink } from "lucide-react";
import type { ReactNode } from "react";

import { safeHttpUrl } from "@/lib/url";

/**
 * Renders an external link only when the URL is a plain http(s) URL; otherwise the label is
 * shown as inert text. Content from external sources is never trusted to be a safe href.
 */
export function SafeLink({ href, children }: { href: string | null | undefined; children: ReactNode }) {
  const safe = safeHttpUrl(href);
  if (!safe) return <span>{children}</span>;
  return (
    <a
      href={safe}
      target="_blank"
      rel="noopener noreferrer nofollow"
      className="inline-flex items-center gap-1 text-primary underline-offset-4 hover:underline"
    >
      {children}
      <ExternalLink aria-hidden className="size-3.5" />
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  );
}
