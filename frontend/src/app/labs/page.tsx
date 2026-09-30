import type { Metadata } from "next";

import { LabsCatalog } from "@/components/lab/labs-catalog";

export const metadata: Metadata = { title: "Hands-on labs" };

export default function LabsPage() {
  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">Hands-on labs</h1>
        <p className="max-w-2xl text-sm text-muted-foreground">
          Practise in a disposable environment: an intentionally vulnerable toy application in a sealed container with
          no network access. Each lab is yours alone and is deleted when you finish or when its time runs out. Never
          use these techniques on systems you do not own or are not authorised to test.
        </p>
      </header>
      <LabsCatalog />
    </div>
  );
}
