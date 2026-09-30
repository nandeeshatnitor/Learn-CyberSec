import { Loader2, SendHorizontal } from "lucide-react";
import { useState } from "react";

import { SafeLink } from "@/components/safe-link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import type { EvidenceRef, HintView, SourceRef, TutorTurn } from "@/lib/learning-types";
import { formatDateTime } from "@/lib/format";

const SID = /^S\d{1,3}$/;

export function EvidenceList({ evidence }: { evidence: EvidenceRef[] }) {
  if (evidence.length === 0) return null;
  return (
    <ul className="mt-2 space-y-1 text-xs" data-testid="evidence">
      {evidence.map((e, index) => (
        <li key={`${index}-${e.source_id}`}>
          <span className="mr-1 font-mono text-muted-foreground">[{SID.test(e.source_id) ? e.source_id : "?"}]</span>
          {e.url ? <SafeLink href={e.url}>{e.title}</SafeLink> : <span>{e.title}</span>}
          {e.excerpt && (
            <details className="mt-1 text-muted-foreground">
              <summary className="cursor-pointer select-none">Show the excerpt</summary>
              <q className="mt-1 block whitespace-pre-line border-l-2 pl-2">{e.excerpt}</q>
            </details>
          )}
        </li>
      ))}
    </ul>
  );
}

export const SUGGESTIONS = [
  "Why does this happen?",
  "What should I investigate next?",
  "What does this parameter mean?",
  "Can you explain the vulnerability?",
];

const OUTCOME_LABEL: Record<string, string> = {
  answered: "From the sources",
  guided: "A nudge, not the answer",
  no_evidence: "Not in the sources",
  refused: "Outside this tutor's scope",
};

/** Right column: the AI tutor. Every technical statement names the source it comes from. */
export function TutorPanel({
  turns,
  busy,
  disabled,
  onAsk,
}: {
  turns: TutorTurn[];
  busy: boolean;
  disabled: boolean;
  onAsk: (question: string) => void;
}) {
  const [question, setQuestion] = useState("");
  const send = (text: string) => {
    const value = text.trim();
    if (value.length < 3 || busy || disabled) return;
    onAsk(value);
    setQuestion("");
  };
  return (
    <Card aria-labelledby="tutor-title">
      <CardHeader>
        <CardTitle id="tutor-title">AI tutor</CardTitle>
        <p className="text-xs text-muted-foreground">
          Answers come from the retrieved sources and cite them. If the sources do not say, the tutor
          says so. It will not hand you the answer to the current task.
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        <ol
          className="max-h-96 space-y-3 overflow-y-auto pr-1"
          aria-live="polite"
          aria-label="Conversation with the tutor"
          data-testid="tutor-log"
        >
          {turns.length === 0 && (
            <li className="text-sm text-muted-foreground">Ask a question about the vulnerability or the task.</li>
          )}
          {turns.map((turn, index) =>
            turn.role === "student" ? (
              <li key={index} className="ml-6 rounded-md bg-accent p-2 text-sm" data-role="student">
                {turn.content}
              </li>
            ) : (
              <li key={index} className="mr-2 space-y-2 rounded-md border p-2 text-sm" data-role="tutor">
                {turn.reply && (
                  <Badge variant={turn.reply.outcome === "answered" ? "default" : "outline"}>
                    {OUTCOME_LABEL[turn.reply.outcome] ?? turn.reply.outcome}
                  </Badge>
                )}
                <p className="leading-relaxed">{turn.content}</p>
                {turn.reply?.parts.map((part, i) => (
                  <div key={i} className="border-l-2 pl-2" data-testid="tutor-claim">
                    <p className="leading-relaxed">{part.text}</p>
                    <EvidenceList evidence={part.evidence} />
                  </div>
                ))}
                {turn.reply?.next_step && (
                  <p className="text-xs text-muted-foreground">Next: {turn.reply.next_step}</p>
                )}
                {turn.reply?.safety_reminder && (
                  <p className="text-xs font-medium text-warning">{turn.reply.safety_reminder}</p>
                )}
              </li>
            ),
          )}
        </ol>
        <div className="flex flex-wrap gap-1">
          {SUGGESTIONS.map((s) => (
            <button
              key={s}
              type="button"
              className="rounded-full border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
              disabled={busy || disabled}
              onClick={() => send(s)}
            >
              {s}
            </button>
          ))}
        </div>
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            send(question);
          }}
        >
          <label htmlFor="tutor-question" className="sr-only">
            Ask the tutor
          </label>
          <Input
            id="tutor-question"
            value={question}
            maxLength={500}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask the tutor…"
            className="h-10 text-sm"
            disabled={busy || disabled}
          />
          <Button type="submit" size="sm" className="h-10" disabled={busy || disabled || question.trim().length < 3}>
            {busy ? <Loader2 aria-hidden className="size-4 animate-spin" /> : <SendHorizontal aria-hidden className="size-4" />}
            <span className="sr-only">Send</span>
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

export function HintsPanel({ hints, taskTitles }: { hints: HintView[]; taskTitles: Record<string, string> }) {
  return (
    <Card aria-labelledby="hints-title">
      <CardHeader>
        <CardTitle id="hints-title">Hints</CardTitle>
      </CardHeader>
      <CardContent>
        {hints.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No hints used yet. Hints get more explicit each time and cost a few points.
          </p>
        ) : (
          <ol className="space-y-3" data-testid="hint-log">
            {hints.map((hint) => (
              <li key={`${hint.task_id}-${hint.number}`} className="rounded-md border p-2 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
                  <span className="font-semibold text-foreground">
                    {hint.label} · {taskTitles[hint.task_id] ?? hint.task_id}
                  </span>
                  <span>
                    −{hint.penalty} · {formatDateTime(hint.revealed_at)}
                  </span>
                </div>
                <p className="mt-1 leading-relaxed">{hint.text}</p>
                <EvidenceList evidence={hint.evidence} />
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}

export function SourcesPanel({ sources }: { sources: SourceRef[] }) {
  return (
    <Card aria-labelledby="sources-title">
      <CardHeader>
        <CardTitle id="sources-title">Sources</CardTitle>
        <p className="text-xs text-muted-foreground">
          Everything in this exercise comes from these public sources. Read them yourself.
        </p>
      </CardHeader>
      <CardContent>
        <ul className="space-y-2 text-sm" data-testid="sources">
          {sources.map((s) => (
            <li key={s.id} id={SID.test(s.id) ? `learn-source-${s.id}` : undefined}>
              <span className="mr-2 font-mono text-xs text-muted-foreground">[{s.id}]</span>
              {s.url ? <SafeLink href={s.url}>{s.title}</SafeLink> : <span>{s.title}</span>}
              <span className="ml-2 space-x-1">
                <Badge variant="muted">{s.source_type.replace(/_/g, " ")}</Badge>
                <Badge variant="outline">{s.reliability_level}</Badge>
              </span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
