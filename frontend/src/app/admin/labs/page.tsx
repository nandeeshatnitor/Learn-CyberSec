import type { Metadata } from "next";

import { AdminCandidateList } from "@/components/admin/admin-views";

export const metadata: Metadata = { title: "Candidate labs" };

export default function CandidateLabsPage() {
  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">Candidate labs</h1>
        <p className="max-w-2xl text-sm text-muted-foreground">
          Labs generated from researched CVE guides. Each is built and tested automatically, then
          reviewed here by a person. Only approved labs are offered to students.
        </p>
      </header>
      <AdminCandidateList />
    </div>
  );
}
