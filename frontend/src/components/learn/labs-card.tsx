"use client";

import { Check, Circle, FlaskConical, Loader2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import * as sandbox from "@/lib/sandbox-client";
import type { SessionLabs } from "@/lib/sandbox-types";

/**
 * Hands-on practice for this lesson: labs that fit the vulnerability class, with the objectives the
 * student has verified so far. Starting one opens the lab page; progress comes back here.
 */
export function LabsCard(props: { labs: SessionLabs | null; sessionId: string; cveId: string }) {
  // Nothing to show (labs disabled, or none fit this vulnerability): render nothing at all.
  if (!props.labs || props.labs.labs.length === 0) return null;
  return <LabsCardBody {...props} labs={props.labs} />;
}

function LabsCardBody({ labs, sessionId, cveId }: { labs: SessionLabs; sessionId: string; cveId: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);
  const from = `?from=${encodeURIComponent(`/learn/${cveId}`)}`;

  async function start(labId: string) {
    setBusy(labId);
    setError(null);
    setRunningId(null);
    const result = await sandbox.startLab(labId, sessionId);
    if (result.ok) {
      router.push(`/lab/${result.data.id}${from}`);
      return;
    }
    setBusy(null);
    setError(result.problem.message);
    const current = await sandbox.currentInstance();
    if (current.ok && current.data.instance?.can_use) setRunningId(current.data.instance.id);
  }

  return (
    <Card data-testid="labs-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FlaskConical aria-hidden className="size-4" /> Hands-on lab
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        {labs.labs.map((entry) => {
          const percent = entry.total ? Math.round((100 * entry.verified) / entry.total) : 0;
          return (
            <section key={entry.lab.id} className="space-y-2" data-testid="lab-entry" aria-label={entry.lab.title}>
              <h3 className="text-sm font-medium">{entry.lab.title}</h3>
              {entry.retired && (
                <p className="text-xs text-muted-foreground" data-testid="lab-retired">
                  An earlier version of this lab, kept so your progress stays accurate. A newer version replaces it.
                </p>
              )}
              <p className="text-xs text-muted-foreground">{entry.lab.summary}</p>
              <div
                role="progressbar"
                aria-label={`${entry.lab.title} objectives`}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={percent}
                aria-valuetext={`${entry.verified} of ${entry.total} objectives verified`}
                className="h-1.5 overflow-hidden rounded-full bg-muted"
              >
                <div className="h-full bg-primary transition-all" style={{ width: `${percent}%` }} />
              </div>
              <p className="text-xs text-muted-foreground" data-testid="lab-progress-text">
                {entry.verified} of {entry.total} objectives verified
              </p>
              <ul className="space-y-1 text-xs">
                {entry.objectives.map((o) => (
                  <li key={o.id} className="flex items-start gap-1.5">
                    {o.verified ? (
                      <Check aria-hidden className="mt-0.5 size-3.5 shrink-0 text-primary" />
                    ) : (
                      <Circle aria-hidden className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
                    )}
                    <span>
                      {o.title}
                      <span className="sr-only">{o.verified ? " (verified)" : " (not yet)"}</span>
                    </span>
                  </li>
                ))}
              </ul>
              {entry.instance_id ? (
                <Button asChild size="sm">
                  <Link href={`/lab/${entry.instance_id}${from}`}>Resume lab</Link>
                </Button>
              ) : entry.retired ? null : (
                <Button size="sm" onClick={() => void start(entry.lab.id)} disabled={busy !== null}>
                  {busy === entry.lab.id && <Loader2 aria-hidden className="size-3.5 animate-spin" />}
                  {entry.last_instance_id ? "Start a fresh lab" : "Start lab"}
                </Button>
              )}
            </section>
          );
        })}
        {error && (
          <p role="alert" className="text-xs text-destructive">
            {error}{" "}
            {runningId && (
              <Link href={`/lab/${runningId}${from}`} className="underline">
                Open it
              </Link>
            )}
          </p>
        )}
        <p className="text-xs text-muted-foreground">
          A lab is a sealed, disposable container with no network access. Practise only on labs and systems you own or
          may test.
        </p>
      </CardContent>
    </Card>
  );
}
