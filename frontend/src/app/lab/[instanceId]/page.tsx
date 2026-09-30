import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { LabWorkspace } from "@/components/lab/lab-workspace";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Lab" };

type Props = {
  params: Promise<{ instanceId: string }>;
  searchParams: Promise<{ from?: string | string[] }>;
};

const UUID = /^[0-9a-fA-F-]{36}$/;
const LESSON = /^\/learn\/CVE-\d{4}-\d{4,19}$/;

export default async function LabPage({ params, searchParams }: Props) {
  const { instanceId } = await params;
  if (!UUID.test(instanceId)) notFound();
  const from = (await searchParams).from;
  // Only a link back into this site's own lessons is accepted: never an arbitrary redirect target.
  const back = typeof from === "string" && LESSON.test(from) ? from : null;
  return <LabWorkspace instanceId={instanceId} backHref={back} />;
}
