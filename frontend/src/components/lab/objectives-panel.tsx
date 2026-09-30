"use client";

import { Check, Circle, Loader2 } from "lucide-react";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { verifyObjective } from "@/lib/sandbox-client";
import type { InstanceView, ObjectiveView, OutcomeView } from "@/lib/sandbox-types";
import { cn } from "@/lib/utils";

const OUTCOME_STYLE: Record<OutcomeView["status"], string> = {
  passed: "border-primary/40 bg-primary/10",
  failed: "border-warning/40 bg-warning/10",
  blocked: "border-muted bg-muted/50",
  error: "border-destructive/40 bg-destructive/10",
};

/**
 * The lab's objectives. Each is checked against what the running lab *does*: a working request
 * for an exploit, a restart-and-retest for a fix. The student is never asked to paste a command.
 */
export function ObjectivesPanel({
  instance,
  onInstance,
}: {
  instance: InstanceView;
  onInstance: (next: InstanceView) => void;
}) {
  const [inputs, setInputs] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [outcomes, setOutcomes] = useState<Record<string, OutcomeView>>({});
  const [error, setError] = useState<string | null>(null);
  const done = new Set(instance.objectives.filter((o) => o.verified).map((o) => o.id));
  const titles = Object.fromEntries(instance.objectives.map((o) => [o.id, o.title]));

  async function verify(objective: ObjectiveView) {
    setBusy(objective.id);
    setError(null);
    const payload = objective.kind === "payload_replay" ? (inputs[objective.id] ?? "") : undefined;
    const result = await verifyObjective(instance.id, objective.id, payload);
    setBusy(null);
    if (!result.ok) {
      setError(result.problem.message);
      return;
    }
    setOutcomes((o) => ({ ...o, [objective.id]: result.data.outcome }));
    onInstance(result.data.instance);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Objectives</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Each objective is checked against how your lab actually behaves, not against the commands you typed.
        </p>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        <ol className="space-y-4" data-testid="lab-objectives">
          {instance.objectives.map((o, index) => {
            const missing = o.requires.filter((r) => !done.has(r));
            const outcome = outcomes[o.id];
            const running = busy === o.id;
            return (
              <li key={o.id} className="space-y-2" data-verified={o.verified}>
                <div className="flex items-start gap-2">
                  {o.verified ? (
                    <Check aria-hidden className="mt-0.5 size-4 shrink-0 text-primary" />
                  ) : (
                    <Circle aria-hidden className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                  )}
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">
                      {index + 1}. {o.title}{" "}
                      <Badge variant={o.verified ? "default" : "muted"} data-testid={`objective-${o.id}-state`}>
                        {o.verified ? "Verified" : "Not yet"}
                      </Badge>
                    </p>
                    <p className="text-sm text-muted-foreground">{o.description}</p>
                  </div>
                </div>
                {o.kind === "payload_replay" && (
                  <div className="ml-6 space-y-1">
                    <label htmlFor={`in-${o.id}`} className="text-xs font-medium">
                      {o.input_label ?? "Your input"}
                    </label>
                    <Input
                      id={`in-${o.id}`}
                      value={inputs[o.id] ?? ""}
                      onChange={(e) => setInputs((i) => ({ ...i, [o.id]: e.target.value }))}
                      placeholder={o.input_hint ?? ""}
                      maxLength={500}
                      spellCheck={false}
                      autoComplete="off"
                      className="font-mono text-xs"
                    />
                  </div>
                )}
                <div className="ml-6 flex flex-wrap items-center gap-2">
                  <Button
                    size="sm"
                    variant={o.verified ? "outline" : "default"}
                    disabled={running || busy !== null || missing.length > 0 || !instance.can_use}
                    onClick={() => void verify(o)}
                  >
                    {running && <Loader2 aria-hidden className="size-3.5 animate-spin" />}
                    {o.kind === "regression" ? "Restart the app and verify my fix" : "Verify"}
                  </Button>
                  {missing.length > 0 && (
                    <span className="text-xs text-muted-foreground">
                      Complete “{titles[missing[0]!] ?? missing[0]}” first.
                    </span>
                  )}
                </div>
                {(outcome || (o.last_detail && !o.verified)) && (
                  <p
                    role="status"
                    data-testid={`objective-${o.id}-outcome`}
                    className={cn(
                      "ml-6 rounded-md border p-2 text-xs",
                      outcome ? OUTCOME_STYLE[outcome.status] : "border-muted bg-muted/50",
                    )}
                  >
                    {outcome?.detail ?? o.last_detail}
                  </p>
                )}
              </li>
            );
          })}
        </ol>
      </CardContent>
    </Card>
  );
}
