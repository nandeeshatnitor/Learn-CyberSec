import { Loader2, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { SafeLink } from "@/components/safe-link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import type { AnswerResult, SessionView, SolutionView, TaskView } from "@/lib/learning-types";

export interface Feedback {
  result: AnswerResult;
  text: string;
}

const RESULT_BADGE: Record<AnswerResult, { label: string; variant: "default" | "warning" | "destructive" }> = {
  correct: { label: "Correct", variant: "default" },
  partially_correct: { label: "Partly correct", variant: "warning" },
  incorrect: { label: "Not yet", variant: "destructive" },
};

export function SolutionBlock({ solution }: { solution: SolutionView }) {
  return (
    <div className="space-y-3 rounded-md border p-4" data-testid="solution">
      <h3 className="text-sm font-semibold">What the sources say</h3>
      <ul className="space-y-3 text-sm">
        {solution.parts.map((part, index) => (
          <li key={`${index}-${part.text.slice(0, 20)}`}>
            {/* Plain text: solution wording comes from third-party pages and is never rendered as HTML. */}
            <span className="leading-relaxed">{part.text}</span>
            <span className="ml-1 font-mono text-xs text-muted-foreground">[{part.source_ids.join(", ")}]</span>
            {part.command && (
              <div className="mt-1">
                <pre className="overflow-x-auto rounded-md border bg-muted p-2 text-xs">
                  <code>{part.command}</code>
                </pre>
                <p className="mt-1 text-xs text-muted-foreground">
                  Quoted from a source. Nothing here runs it: use it only in your own lab.
                </p>
              </div>
            )}
          </li>
        ))}
      </ul>
      {solution.evidence.length > 0 && (
        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer select-none">Show the source excerpts</summary>
          <ul className="mt-2 space-y-2">
            {solution.evidence.map((e, index) => (
              <li key={`${index}-${e.source_id}`} className="border-l-2 pl-2">
                <SafeLink href={e.url}>
                  [{e.source_id}] {e.title}
                </SafeLink>
                {e.excerpt && <q className="mt-1 block whitespace-pre-line">{e.excerpt}</q>}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

/** Centre column: the current task, research context, answer box, hint and solution controls. */
export function TaskPanel({
  session,
  task,
  draft,
  onDraft,
  feedback,
  solution,
  busy,
  onSubmit,
  onHint,
  onReveal,
  onNext,
}: {
  session: SessionView;
  task: TaskView;
  draft: string;
  onDraft: (value: string) => void;
  feedback: Feedback | undefined;
  solution: SolutionView | undefined;
  busy: string | null;
  onSubmit: () => void;
  onHint: () => void;
  onReveal: () => void;
  onNext?: () => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const open = task.status === "open" && session.status === "in_progress";
  const nextHint = task.hints_revealed + 1;
  const badge = feedback ? RESULT_BADGE[feedback.result] : null;
  return (
    <section aria-labelledby="task-title" className="space-y-4" data-testid="task-panel">
      <Card>
        <CardHeader>
          <p className="text-xs uppercase tracking-wide text-muted-foreground">
            Task {task.order} of {session.tasks.length}
          </p>
          <CardTitle id="task-title" className="text-xl">
            {task.title}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <p className="text-base leading-relaxed" data-testid="task-prompt">
            {task.prompt}
          </p>

          <div>
            <h3 className="text-sm font-semibold">A complete answer</h3>
            <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
              {task.verification_criteria.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          </div>

          <div className="rounded-md border p-4" data-testid="research-context">
            <h3 className="text-sm font-semibold">Research context</h3>
            <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
              Investigate first: read the sources yourself before you answer.
            </p>
            {session.cve.description && (
              <p className="mt-2 text-sm leading-relaxed">
                <span className="text-muted-foreground">{session.cve.cve_id}: </span>
                {session.cve.description}
              </p>
            )}
            {session.cve.affected.length > 0 && (
              <p className="mt-1 text-xs text-muted-foreground">
                Affected software as reported: {session.cve.affected.join(", ")}
              </p>
            )}
            {task.context_sources.length > 0 && (
              <ul className="mt-3 space-y-1 text-sm">
                {task.context_sources.map((s) => (
                  <li key={s.id}>
                    <span className="mr-2 font-mono text-xs text-muted-foreground">[{s.id}]</span>
                    {s.url ? <SafeLink href={s.url}>{s.title}</SafeLink> : <span>{s.title}</span>}
                    <Badge variant="outline" className="ml-2">
                      {s.reliability_level}
                    </Badge>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {open && (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                onSubmit();
              }}
              className="space-y-3"
            >
              <label htmlFor="answer" className="text-sm font-semibold">
                Your answer
              </label>
              <Textarea
                id="answer"
                value={draft}
                maxLength={1000}
                onChange={(e) => onDraft(e.target.value)}
                placeholder="Write your answer in your own words…"
                disabled={busy !== null}
              />
              <div className="flex flex-wrap items-center gap-3">
                <Button type="submit" disabled={busy !== null || draft.trim().length < 3}>
                  {busy === "answer" && <Loader2 aria-hidden className="size-4 animate-spin" />}
                  Submit answer
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={onHint}
                  disabled={busy !== null || task.next_hint_penalty === null}
                >
                  {task.next_hint_penalty === null
                    ? "All hints shown"
                    : `Get Hint ${nextHint} (−${task.next_hint_penalty} points)`}
                </Button>
                {!confirming && (
                  <Button
                    type="button"
                    variant="ghost"
                    onClick={() => setConfirming(true)}
                    disabled={busy !== null || !task.solution_available}
                    title={task.solution_available ? undefined : "Submit an answer first"}
                  >
                    Reveal solution (−{task.solution_penalty})
                  </Button>
                )}
              </div>
              {!task.solution_available && (
                <p className="text-xs text-muted-foreground">
                  Try the task first: the solution becomes available after your first answer.
                </p>
              )}
              {confirming && (
                <div
                  role="alertdialog"
                  aria-label="Confirm revealing the solution"
                  className="rounded-md border border-warning/40 bg-warning/10 p-3 text-sm"
                >
                  <p>
                    This finishes the task without credit and costs {task.solution_penalty} points.
                    Reveal the solution?
                  </p>
                  <div className="mt-2 flex gap-2">
                    <Button
                      type="button"
                      size="sm"
                      onClick={() => {
                        setConfirming(false);
                        onReveal();
                      }}
                    >
                      Yes, reveal it
                    </Button>
                    <Button type="button" size="sm" variant="outline" onClick={() => setConfirming(false)}>
                      Keep trying
                    </Button>
                  </div>
                </div>
              )}
            </form>
          )}

          {feedback && badge && (
            <div className="space-y-2 rounded-md border p-4" role="status" data-testid="feedback">
              <Badge variant={badge.variant}>{badge.label}</Badge>
              <p className="text-sm leading-relaxed">{feedback.text}</p>
            </div>
          )}

          {task.status === "correct" && (
            <p className="text-sm font-medium text-primary">Task complete: you answered it correctly.</p>
          )}
          {task.status === "revealed" && (
            <p className="text-sm font-medium text-muted-foreground">
              Task finished with the solution revealed.
            </p>
          )}
          {solution && <SolutionBlock solution={solution} />}
          {onNext && task.status !== "open" && task.status !== "locked" && (
            <Button type="button" onClick={onNext}>
              Continue to the next task
            </Button>
          )}
        </CardContent>
      </Card>

      <p className="flex items-start gap-2 text-xs text-muted-foreground">
        <ShieldAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
        <span>{session.safety_notice}</span>
      </p>
    </section>
  );
}
