"use client";

import Link from "next/link";
import { Loader2 } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { HintsPanel, SourcesPanel, TutorPanel } from "@/components/learn/side-panels";
import { LabsCard } from "@/components/learn/labs-card";
import { ProgressPanel } from "@/components/learn/progress-panel";
import { Summary } from "@/components/learn/summary";
import { TaskPanel, type Feedback } from "@/components/learn/task-panel";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import * as api from "@/lib/learning-client";
import * as sandbox from "@/lib/sandbox-client";
import type { SessionLabs } from "@/lib/sandbox-types";
import type { HintView, SessionView, SolutionView, TutorTurn } from "@/lib/learning-types";
import { fetchStatus } from "@/lib/research-client";
import type { ResearchProblem } from "@/lib/research-types";

type Phase =
  | { kind: "loading" }
  | { kind: "noguide" }
  | { kind: "problem"; problem: ResearchProblem }
  | { kind: "intro"; session: SessionView | null }
  | { kind: "session" };

/**
 * The learning workspace: objectives and progress on the left, the current task in the middle, the
 * AI tutor, hints and sources on the right. All state lives on the server (a session); this only
 * renders it and sends the student's actions.
 */
export function LearningWorkspace({ cveId }: { cveId: string }) {
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const [session, setSession] = useState<SessionView | null>(null);
  const [hints, setHints] = useState<HintView[]>([]);
  const [turns, setTurns] = useState<TutorTurn[]>([]);
  const [feedback, setFeedback] = useState<Record<string, Feedback>>({});
  const [solutions, setSolutions] = useState<Record<string, SolutionView>>({});
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [viewTask, setViewTask] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [labs, setLabs] = useState<SessionLabs | null>(null);
  const alive = useRef(true);

  /** Take a new session state. `stay` keeps the student on the task they just finished so they can
   * read the feedback and solution before choosing to continue. */
  const adopt = useCallback((next: SessionView, stay: string | null = null) => {
    setSession(next);
    setViewTask(stay);
  }, []);

  const loadDetails = useCallback(
    async (s: SessionView) => {
      const [h, t] = await Promise.all([api.listHints(s.id), api.tutorHistory(s.id)]);
      if (!alive.current) return;
      if (h.ok) setHints(h.data.hints);
      if (t.ok) setTurns(t.data.messages);
      const found: Record<string, SolutionView> = {};
      await Promise.all(
        s.tasks
          .filter((task) => task.status === "correct" || task.status === "revealed")
          .map(async (task) => {
            const r = await api.getSolution(s.id, task.id);
            if (r.ok) found[task.id] = r.data;
          }),
      );
      if (alive.current) setSolutions((prev) => ({ ...found, ...prev }));
    },
    [],
  );

  useEffect(() => {
    alive.current = true;
    void (async () => {
      const existing = await api.sessionForCve(cveId);
      if (!alive.current) return;
      if (existing.ok) {
        const s = existing.data;
        setSession(s);
        if (s.status === "in_progress" || s.status === "completed") {
          setPhase({ kind: "session" });
          await loadDetails(s);
        } else if (s.status === "not_started") {
          setPhase({ kind: "intro", session: s });
        } else {
          setPhase({ kind: "intro", session: null });
        }
        return;
      }
      if (existing.problem.kind !== "not_found") {
        setPhase({ kind: "problem", problem: existing.problem });
        return;
      }
      const status = await fetchStatus(cveId);
      if (!alive.current) return;
      if (status.ok && status.data.guide_available) setPhase({ kind: "intro", session: null });
      else if (status.ok) setPhase({ kind: "noguide" });
      else setPhase({ kind: "problem", problem: status.problem });
    })();
    return () => {
      alive.current = false;
    };
  }, [cveId, loadDetails]);

  // Hands-on labs that fit this lesson, with the objectives verified so far. Optional: when labs are
  // not enabled (or none fit) this simply stays empty and the lesson works exactly as before.
  const sessionId = session?.id ?? null;
  useEffect(() => {
    if (!sessionId || phase.kind !== "session") return;
    let live = true;
    void sandbox.sessionLabs(sessionId).then((result) => {
      if (live && result.ok) setLabs(result.data);
    });
    return () => {
      live = false;
    };
  }, [sessionId, phase.kind]);

  async function run<T>(label: string, action: () => Promise<api.Outcome<T>>, onOk: (data: T) => void) {
    setBusy(label);
    setError(null);
    const result = await action();
    if (!alive.current) return;
    setBusy(null);
    if (result.ok) onOk(result.data);
    else setError(result.problem.message);
  }

  const begin = () =>
    run(
      "start",
      async () => {
        const created = phase.kind === "intro" && phase.session ? { ok: true as const, data: phase.session } : await api.createSession(cveId);
        if (!created.ok) return created;
        return api.startSession(created.data.id);
      },
      (s) => {
        adopt(s);
        setPhase({ kind: "session" });
        void loadDetails(s);
      },
    );

  if (phase.kind === "loading") {
    return (
      <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 aria-hidden className="size-4 animate-spin" /> Loading your learning session…
      </p>
    );
  }
  if (phase.kind === "noguide") {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Generate the learning guide first</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p className="text-muted-foreground">
            The exercises are built from public research about this CVE. Generate the guide, then come back
            to start a session.
          </p>
          <Button asChild>
            <Link href={`/cves/${cveId}#learning-guide`}>Go to the CVE page</Link>
          </Button>
        </CardContent>
      </Card>
    );
  }
  if (phase.kind === "problem") {
    return (
      <p role="alert" className="text-sm text-destructive" data-testid="learn-error">
        {phase.problem.message}
      </p>
    );
  }
  if (phase.kind === "intro") {
    return (
      <Card data-testid="intro">
        <CardHeader>
          <CardTitle className="text-xl">Learn {cveId} step by step</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <p className="leading-relaxed">
            You will work through a few tasks: understand the vulnerability, investigate the sources, try to
            answer, get feedback, and ask for hints only when you need them. The full solution stays hidden until
            you answer correctly or choose to reveal it.
          </p>
          <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
            <li>Hints get more explicit each time: −5, −10 and −15 points. A solution costs −30.</li>
            <li>An AI tutor answers questions from the sources and cites them.</li>
            <li>Reproduction is for a local or authorized lab only.</li>
          </ul>
          {error && (
            <p role="alert" className="text-destructive">
              {error}
            </p>
          )}
          <Button onClick={() => void begin()} disabled={busy !== null}>
            {busy === "start" && <Loader2 aria-hidden className="size-4 animate-spin" />}
            {phase.session ? "Begin the session" : "Start learning session"}
          </Button>
        </CardContent>
      </Card>
    );
  }
  if (!session) return null;

  const current = session.tasks.find((t) => t.id === session.current_task_id) ?? null;
  const active =
    session.tasks.find((t) => t.id === viewTask) ??
    current ??
    session.tasks[session.tasks.length - 1] ??
    null;
  const titles = Object.fromEntries(session.tasks.map((t) => [t.id, t.title]));
  const inProgress = session.status === "in_progress";

  return (
    <div className="space-y-4">
      {error && (
        <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive" data-testid="learn-error">
          {error}
        </p>
      )}
      {session.status === "completed" && <Summary session={session} labs={labs} />}
      <div className="grid gap-6 lg:grid-cols-[260px_minmax(0,1fr)_340px]" data-testid="workspace">
        <aside className="space-y-4" aria-label="Objectives and progress">
          <ProgressPanel session={session} activeId={active?.id ?? null} onSelect={setViewTask} />
          <LabsCard labs={labs} sessionId={session.id} cveId={cveId} />
        </aside>

        <main className="min-w-0 space-y-4">
          {active && (
            <TaskPanel
              session={session}
              task={active}
              draft={drafts[active.id] ?? ""}
              onDraft={(value) => setDrafts((d) => ({ ...d, [active.id]: value }))}
              feedback={feedback[active.id]}
              solution={solutions[active.id]}
              busy={busy}
              onSubmit={() =>
                void run(
                  "answer",
                  () => api.submitAnswer(session.id, active.id, drafts[active.id] ?? ""),
                  (r) => {
                    setFeedback((f) => ({ ...f, [active.id]: { result: r.result, text: r.feedback } }));
                    if (r.solution) setSolutions((s) => ({ ...s, [active.id]: r.solution! }));
                    if (r.result === "correct") setDrafts((d) => ({ ...d, [active.id]: "" }));
                    adopt(r.session, r.result === "correct" ? active.id : viewTask);
                  },
                )
              }
              onHint={() =>
                void run(
                  "hint",
                  () => api.revealHint(session.id, active.id, active.hints_revealed + 1),
                  (r) => {
                    setHints((h) => [...h, r.hint]);
                    setSession(r.session);
                  },
                )
              }
              onNext={current && current.id !== active.id ? () => setViewTask(null) : undefined}
              onReveal={() =>
                void run(
                  "solution",
                  () => api.revealSolution(session.id, active.id),
                  (r) => {
                    setSolutions((s) => ({ ...s, [active.id]: r.solution }));
                    adopt(r.session, active.id);
                  },
                )
              }
            />
          )}
          {session.can_complete && (
            <Card>
              <CardContent className="flex flex-wrap items-center justify-between gap-3 p-5">
                <p className="text-sm">Every task is finished. Complete the session to see your score.</p>
                <Button
                  onClick={() => void run("complete", () => api.completeSession(session.id), adopt)}
                  disabled={busy !== null}
                >
                  Complete session
                </Button>
              </CardContent>
            </Card>
          )}
          {session.notes.length > 0 && (
            <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
              {session.notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          )}
        </main>

        <aside className="space-y-4" aria-label="Tutor, hints and sources">
          <TutorPanel
            turns={turns}
            busy={busy === "tutor"}
            disabled={!inProgress}
            onAsk={(question) => {
              setTurns((t) => [
                ...t,
                { role: "student", task_id: active?.id ?? null, content: question, reply: null, created_at: new Date().toISOString() },
              ]);
              void run(
                "tutor",
                () => api.askTutor(session.id, question, active?.id ?? null),
                (reply) =>
                  setTurns((t) => [
                    ...t,
                    { role: "tutor", task_id: active?.id ?? null, content: reply.message, reply, created_at: reply.created_at },
                  ]),
              );
            }}
          />
          <HintsPanel hints={hints} taskTitles={titles} />
          <SourcesPanel sources={session.sources} />
        </aside>
      </div>
    </div>
  );
}
