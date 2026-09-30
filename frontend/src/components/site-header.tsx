import { ShieldCheck } from "lucide-react";
import Link from "next/link";

export function SiteHeader() {
  return (
    <header className="border-b bg-background/80">
      <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-4">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <ShieldCheck aria-hidden className="size-5 text-primary" />
          <span>
            CVE Learning <span className="text-primary">Explorer</span>
          </span>
        </Link>
      </div>
    </header>
  );
}
