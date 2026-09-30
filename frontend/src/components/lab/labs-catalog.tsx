"use client";

import { Loader2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import * as api from "@/lib/sandbox-client";
import type { InstanceView, LabView } from "@/lib/sandbox-types";
import type { ResearchProblem } from "@/lib/research-types";

/** The catalogue of labs, and a way back into the one already running. */
export function LabsCatalog() {
  const router = useRouter();
  const [labs, setLabs] = useState<LabView[] | null>(null);
  const [current, setCurrent] = useState<InstanceView | null>(null);
  const [problem, setProblem] = useState<ResearchProblem | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      const [list, running] = await Promise.all([api.listLabs(), api.currentInstance()]);
      if (!alive) return;
      if (!list.ok) setProblem(list.problem);
      else setLabs(list.data);
      if (running.ok) setCurrent(running.data.instance);
    })();
    return () => {
      alive = false;
    };
  }, []);

  async function start(labId: string) {
    setBusy(labId);
    setError(null);
    const result = await api.startLab(labId);
    setBusy(null);
    if (result.ok) router.push(`/lab/${result.data.id}`);
    else setError(result.problem.message);
  }

  if (problem) {
    return (
      <p role="status" className="text-sm text-muted-foreground" data-testid="labs-unavailable">
        {problem.kind === "disabled" ? "Hands-on labs are not enabled on this server." : problem.message}
      </p>
    );
  }
  if (!labs) {
    return (
      <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 aria-hidden className="size-4 animate-spin" /> Loading labs…
      </p>
    );
  }
  return (
    <div className="space-y-4">
      {current && current.can_use && (
        <Card data-testid="resume-lab">
          <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4 text-sm">
            <span>
              You have a lab running: <strong>{current.lab.title}</strong>.
            </span>
            <Button asChild>
              <Link href={`/lab/${current.id}`}>Resume it</Link>
            </Button>
          </CardContent>
        </Card>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <ul className="grid gap-4 sm:grid-cols-2" data-testid="lab-list">
        {labs.map((lab) => (
          <li key={lab.id}>
            <Card className="h-full">
              <CardHeader>
                <CardTitle className="flex flex-wrap items-center gap-2 text-lg">
                  {lab.title} <Badge variant="muted">{lab.difficulty}</Badge>
                  {lab.cwe_ids.map((cwe) => (
                    <Badge key={cwe} variant="outline">
                      {cwe}
                    </Badge>
                  ))}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 text-sm">
                <p className="text-muted-foreground">{lab.summary}</p>
                <p className="text-xs text-muted-foreground">
                  Lasts {lab.resources.timeout_minutes} minutes · no network access · {lab.objectives.length} objectives
                </p>
                <Button onClick={() => void start(lab.id)} disabled={busy !== null || (current?.can_use ?? false)}>
                  {busy === lab.id && <Loader2 aria-hidden className="size-4 animate-spin" />} Start lab
                </Button>
              </CardContent>
            </Card>
          </li>
        ))}
      </ul>
    </div>
  );
}
