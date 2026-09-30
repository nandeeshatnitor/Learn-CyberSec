import { BookOpen, FlaskConical, Lightbulb, Wrench } from "lucide-react";
import Link from "next/link";

import { ApiStatus } from "@/components/api-status";
import { CveSearchForm } from "@/components/cve-search-form";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EXAMPLE_CVES } from "@/lib/cve";

// Renders the live API status, so it must never be prerendered at build time.
export const dynamic = "force-dynamic";

const LEARNING_STEPS = [
  { icon: BookOpen, title: "Understand it", text: "What the flaw is, who is affected, and why it exists." },
  { icon: FlaskConical, title: "Reproduce it safely", text: "Prerequisites and evidence of success in an authorised, local lab." },
  { icon: Lightbulb, title: "Get hints", text: "Guided nudges instead of spoilers." },
  { icon: Wrench, title: "Fix it", text: "Remediation, with every claim linked to its source." },
];

export default function HomePage() {
  return (
    <div className="space-y-14">
      <section className="space-y-6">
        <div className="flex flex-wrap items-center gap-3">
          <span className="font-mono text-sm text-primary">$ cve --learn</span>
          <ApiStatus />
        </div>
        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">CVE Learning Explorer</h1>
        <p className="max-w-2xl text-lg text-muted-foreground">
          Search a CVE and study it like a lesson: what it is, who it affects, how it works, how to
          reproduce it in a lab you control, and how to fix it, with the original sources cited.
        </p>
        <CveSearchForm autoFocus />
      </section>

      <section aria-labelledby="examples-title" className="space-y-4">
        <h2 id="examples-title" className="text-xl font-semibold">
          Example CVEs
        </h2>
        <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {EXAMPLE_CVES.map((cve) => (
            <li key={cve.id}>
              <Link
                href={`/cves/${cve.id}`}
                className="block h-full rounded-lg border bg-card p-4 transition-colors hover:border-primary/60"
              >
                <span className="font-mono text-sm text-primary">{cve.id}</span>
                <span className="mt-1 block font-medium">{cve.name}</span>
                <span className="text-sm text-muted-foreground">{cve.summary}</span>
              </Link>
            </li>
          ))}
        </ul>
        <p className="text-sm text-muted-foreground">
          Only a handful of sample records exist so far. Retrieval from public sources is not
          implemented yet.
        </p>
      </section>

      <section aria-labelledby="how-title" className="space-y-4">
        <h2 id="how-title" className="text-xl font-semibold">
          How it will work
        </h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {LEARNING_STEPS.map(({ icon: Icon, title, text }) => (
            <Card key={title}>
              <CardHeader className="flex-row items-center gap-3">
                <Icon aria-hidden className="size-5 text-primary" />
                <CardTitle className="text-base">{title}</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-muted-foreground">{text}</CardContent>
            </Card>
          ))}
        </div>
      </section>

      <section
        aria-labelledby="disclaimer-title"
        className="rounded-lg border border-warning/40 bg-warning/10 p-5"
      >
        <h2 id="disclaimer-title" className="font-semibold">
          Educational disclaimer
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          This project exists to teach defensive security. Do not use anything you learn here
          against systems you do not own or lack written authorisation to test. Vulnerability
          write-ups gathered from external sources are untrusted: nothing is executed
          automatically, and you should verify details against the original advisories.
        </p>
      </section>
    </div>
  );
}
