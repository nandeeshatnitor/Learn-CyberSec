import { Check, CircleDot, Lock } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { SessionView, TaskView } from "@/lib/learning-types";
import { cn } from "@/lib/utils";

const STATUS_TEXT: Record<TaskView["status"], string> = {
  locked: "locked",
  open: "current",
  correct: "answered",
  revealed: "solution shown",
};

/** Left column: objectives, task list with status, progress, score and prerequisites. */
export function ProgressPanel({
  session,
  activeId,
  onSelect,
}: {
  session: SessionView;
  activeId: string | null;
  onSelect: (taskId: string) => void;
}) {
  const { progress } = session;
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Progress</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div
            role="progressbar"
            aria-label="Learning progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progress.percent}
            aria-valuetext={`${progress.resolved} of ${progress.total} tasks finished`}
            className="h-2 overflow-hidden rounded-full bg-muted"
          >
            <div className="h-full bg-primary transition-all" style={{ width: `${progress.percent}%` }} />
          </div>
          <p className="text-sm text-muted-foreground" data-testid="progress-text">
            {progress.resolved} of {progress.total} tasks finished
          </p>
          <dl className="grid grid-cols-2 gap-2 text-sm">
            <div>
              <dt className="text-muted-foreground">Score</dt>
              <dd className="text-lg font-semibold" data-testid="score">
                {session.score}
                <span className="text-sm font-normal text-muted-foreground"> / {session.max_score}</span>
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Hints used</dt>
              <dd className="text-lg font-semibold" data-testid="hints-used">
                {session.hints_used}
              </dd>
            </div>
          </dl>
          {session.solution_revealed && <Badge variant="warning">A solution was revealed</Badge>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Learning objectives</CardTitle>
        </CardHeader>
        <CardContent>
          <ol className="space-y-1" data-testid="objectives">
            {session.tasks.map((task) => {
              const done = task.status === "correct" || task.status === "revealed";
              const locked = task.status === "locked";
              return (
                <li key={task.id}>
                  <button
                    type="button"
                    disabled={locked}
                    onClick={() => onSelect(task.id)}
                    aria-current={activeId === task.id ? "step" : undefined}
                    data-status={task.status}
                    className={cn(
                      "flex w-full items-start gap-2 rounded-md px-2 py-1.5 text-left text-sm",
                      activeId === task.id ? "bg-accent" : "hover:bg-accent/60",
                      locked && "cursor-not-allowed text-muted-foreground",
                    )}
                  >
                    {done ? (
                      <Check aria-hidden className="mt-0.5 size-4 shrink-0 text-primary" />
                    ) : locked ? (
                      <Lock aria-hidden className="mt-0.5 size-4 shrink-0" />
                    ) : (
                      <CircleDot aria-hidden className="mt-0.5 size-4 shrink-0" />
                    )}
                    <span>
                      {task.objective}
                      <span className="sr-only"> ({STATUS_TEXT[task.status]})</span>
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Before you start</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="list-disc space-y-2 pl-5 text-sm" data-testid="prerequisites">
            {session.prerequisites.map((p) => (
              <li key={p.text}>
                {p.text}
                {p.source_ids.length > 0 && (
                  <span className="ml-1 font-mono text-xs text-muted-foreground">
                    [{p.source_ids.join(", ")}]
                  </span>
                )}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
