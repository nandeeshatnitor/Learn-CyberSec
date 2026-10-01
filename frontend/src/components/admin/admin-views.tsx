"use client";

import { AdminGate } from "@/components/admin/admin-gate";
import { CandidateList } from "@/components/admin/candidate-list";
import { CandidateReview } from "@/components/admin/candidate-review";

/**
 * The admin pages are server components, which cannot hand a function to a client component, so
 * the sign-in gate and what it protects are composed here, on the client side of the boundary.
 */
export function AdminCandidateList() {
  return <AdminGate>{(_reviewer, signOut) => <CandidateList onSignedOut={signOut} />}</AdminGate>;
}

export function AdminCandidateReview({ id }: { id: string }) {
  return (
    <AdminGate>
      {(_reviewer, signOut) => <CandidateReview id={id} onSignedOut={signOut} />}
    </AdminGate>
  );
}
