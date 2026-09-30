import type { Metadata } from "next";
import type { ReactNode } from "react";

import { SiteFooter } from "@/components/site-footer";
import { SiteHeader } from "@/components/site-header";

import "./globals.css";

export const metadata: Metadata = {
  title: { default: "CVE Learning Explorer", template: "%s · CVE Learning Explorer" },
  description:
    "Learn how publicly known vulnerabilities work: what they are, why they happen, and how to fix them.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <SiteHeader />
        <main className="mx-auto max-w-5xl px-4 py-10">{children}</main>
        <SiteFooter />
      </body>
    </html>
  );
}
