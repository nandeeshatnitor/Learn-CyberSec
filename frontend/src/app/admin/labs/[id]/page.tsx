import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { AdminCandidateReview } from "@/components/admin/admin-views";

export const metadata: Metadata = { title: "Review candidate lab" };

type Props = { params: Promise<{ id: string }> };

const UUID = /^[0-9a-fA-F-]{36}$/;

export default async function ReviewPage({ params }: Props) {
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  return <AdminCandidateReview id={id} />;
}
