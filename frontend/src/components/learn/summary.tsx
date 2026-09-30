import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { SessionView } from "@/lib/learning-types";
import { formatDateTime } from "@/lib/format";

export function Summary({ session }: { session: SessionView }) {
  return (
    <Card data-testid="summary">
      <CardHeader>
        <CardTitle className="text-xl">Session complete</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          You worked through {session.cve_id}
          {session.completed_at ? ` and finished ${formatDateTime(session.completed_at)}` : ""}. The score is only a
          rough measure of how much help you needed: what matters is what you now understand.
        </p>
        <dl className="grid grid-cols-3 gap-3 text-sm">
          <div>
            <dt className="text-muted-foreground">Final score</dt>
            <dd className="text-2xl font-semibold" data-testid="final-score">
              {session.score}
              <span className="text-sm font-normal text-muted-foreground"> / {session.max_score}</span>
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Hints used</dt>
            <dd className="text-2xl font-semibold">{session.hints_used}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Tasks</dt>
            <dd className="text-2xl font-semibold">
              {session.progress.resolved}/{session.progress.total}
            </dd>
          </div>
        </dl>
        <ul className="space-y-1 text-sm">
          {session.tasks.map((t) => (
            <li key={t.id} className="flex items-center justify-between gap-2">
              <span>{t.title}</span>
              <Badge variant={t.status === "correct" ? "default" : "muted"}>
                {t.status === "correct" ? "Answered" : "Solution shown"}
              </Badge>
            </li>
          ))}
        </ul>
        {session.solution_revealed && (
          <p className="text-xs text-muted-foreground">
            At least one solution was revealed. Revisit those tasks and try to explain them in your own words.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
