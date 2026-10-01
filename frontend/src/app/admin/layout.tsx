import type { Metadata } from "next";
import type { ReactNode } from "react";

// The review interface is for reviewers only: keep it out of search indexes and caches.
export const metadata: Metadata = { robots: { index: false, follow: false } };
export const dynamic = "force-dynamic";

export default function AdminLayout({ children }: { children: ReactNode }) {
  return <div className="space-y-6">{children}</div>;
}
