"use client";

import { Check, Loader2 } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { GuideView } from "@/components/research/guide-view";
import { SectionCard } from "@/components/section-card";
import { Button } from "@/components/ui/button";
import { fetchGuide, fetchStatus, startResearch, type Outcome } from "@/lib/research-client";
import type { ResearchGuideResponse, ResearchProblem, ResearchStatus } from "@/lib/research-types";
import { formatDateTime } from "@/lib/format";

const STEPS = [
  { key: "queued", label: "Queued" },
  { key: "researching", label: "Researching" },
  { key: "synthesizing", label: "Synthesizing" },
  { key: "ready", label: "Ready" },
] as const;

const ACTIVE = new Set(["queued", "researching", "synthesizing"]);
const MIN_POLL_MS = 2_000;
const MAX_POLL_MS = 10_000;
const GIVE_UP_AFTER_MS = 15 * 60_000;
const MAX_CONSECUTIVE_ERRORS = 5;

type View =
  | { phase: "loading" }
  | { phase: "idle"; status: ResearchStatus }
  | { phase: "active"; status: ResearchStatus }
  | { phase: "ready"; response: ResearchGuideResponse; notice?: string }
  | { phase: "failed"; status: ResearchStatus }
  | { phase: "problem"; problem: ResearchProblem };

export function GenerateGuidePanel({ cveId }: { cveId: string }) {
  const [view, setView] = useState<View>({ phase: "loading" });
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const controller = useRef<AbortController | null>(null);

  const stopPolling = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    controller.current?.abort();
    controller.current = null;
  }, []);

  const signal = useCallback(() => {
    controller.current?.abort();
    controller.current = new AbortController();
    return controller.current.signal;
  }, []);

  const showGuide = useCallback(
    async (previous?: ResearchGuideResponse): Promise<void> => {
      const sig = signal();
      const result = await fetchGuide(cveId, sig);
      if (!alive.current || sig.aborted) return; // superseded by a newer request or unmounted
      if (result.ok) setView({ phase: "ready", response: result.data });
      else if (previous) setView({ phase: "ready", response: previous, notice: result.problem.message });
      else setView({ phase: "problem", problem: result.problem });
    },
    [cveId, signal],
  );

  /** Follow a run until it finishes. Backs off gently and gives up after a while. */
  const poll = useCallback(
    (first: ResearchStatus, previous?: ResearchGuideResponse) => {
      const startedAt = Date.now();
      let delay = Math.min(Math.max((first.poll_after_seconds ?? 3) * 1000, MIN_POLL_MS), MAX_POLL_MS);
      let errors = 0;

      const tick = async (): Promise<void> => {
        if (!alive.current) return;
        const sig = signal();
        const result: Outcome<ResearchStatus> = await fetchStatus(cveId, sig);
        if (!alive.current || sig.aborted) return;
        if (!result.ok) {
          errors += 1;
          if (errors >= MAX_CONSECUTIVE_ERRORS || result.problem.kind === "rate_limited") {
            setView({ phase: "problem", problem: result.problem });
            return;
          }
        } else {
          errors = 0;
          const status = result.data;
          if (status.status === "ready") return showGuide(previous);
          if (status.status === "failed" || status.status === "not_started") {
            if (previous || status.guide_available) return showGuide(previous);
            setView({ phase: "failed", status });
            return;
          }
          setView({ phase: "active", status });
        }
        if (Date.now() - startedAt > GIVE_UP_AFTER_MS) {
          setView({
            phase: "problem",
            problem: { kind: "unavailable", message: "This is taking longer than expected. Reload the page later to see the result." },
          });
          return;
        }
        delay = Math.min(delay * 1.3, MAX_POLL_MS);
        timer.current = setTimeout(() => void tick(), delay);
      };
      timer.current = setTimeout(() => void tick(), delay);
    },
    [cveId, showGuide, signal],
  );

  // Initial state: what has already been generated for this CVE?
  useEffect(() => {
    alive.current = true;
    void (async () => {
      const sig = signal();
      const result = await fetchStatus(cveId, sig);
      if (!alive.current || sig.aborted) return;
      if (!result.ok) {
        // A missing research feature must not break the CVE page: offer the button anyway.
        setView({ phase: "problem", problem: result.problem });
        return;
      }
      const status = result.data;
      if (ACTIVE.has(status.status)) {
        setView({ phase: "active", status });
        poll(status);
      } else if (status.guide_available) {
        await showGuide();
      } else if (status.status === "failed") {
        setView({ phase: "failed", status });
      } else {
        setView({ phase: "idle", status });
      }
    })();
    return () => {
      alive.current = false;
      stopPolling();
    };
  }, [cveId, poll, showGuide, signal, stopPolling]);

  async function start(refresh = false) {
    const previous = view.phase === "ready" ? view.response : undefined;
    setBusy(true);
    stopPolling();
    const sig = signal();
    const result = await startResearch(cveId, refresh, sig);
    if (!alive.current || sig.aborted) return;
    setBusy(false);
    if (!result.ok) {
      if (previous) setView({ phase: "ready", response: previous, notice: result.problem.message });
      else setView({ phase: "problem", problem: result.problem });
      return;
    }
    const status = result.data;
    if (status.status === "ready") {
      await showGuide(previous);
      if (refresh && status.cached && alive.current) {
        const when = formatDateTime(status.refresh_available_at);
        const note = `A current guide already exists${when ? `; it can be regenerated after ${when}` : ""}.`;
        setView((now) => (now.phase === "ready" ? { ...now, notice: note } : now));
      }
    } else if (ACTIVE.has(status.status)) {
      setView({ phase: "active", status });
      poll(status, previous);
    } else {
      setView({ phase: "failed", status });
    }
  }

  if (view.phase === "ready") {
    return (
      <div className="space-y-4">
        <GuideView response={view.response} />
        <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground" data-testid="regenerate">
          <Button variant="outline" size="sm" onClick={() => void start(true)} disabled={busy}>
            Regenerate guide
          </Button>
          {view.notice && <span role="status">{view.notice}</span>}
        </div>
      </div>
    );
  }

  return (
    <SectionCard id="learning-guide" title="Learning guide" unavailable={view.phase === "idle" || view.phase === "loading"}>
      {view.phase === "loading" && <p className="text-sm text-muted-foreground">Checking for an existing guide…</p>}
      {view.phase === "idle" && (
        <Intro busy={busy} onStart={() => void start()} />
      )}
      {view.phase === "active" && <Progress status={view.status} />}
      {view.phase === "failed" && (
        <div className="space-y-3">
          <p role="alert" className="text-sm text-destructive" data-testid="research-error">
            {view.status.error?.message ?? "Generating the guide failed."}
          </p>
          <Button onClick={() => void start()} disabled={busy}>
            Try again
          </Button>
        </div>
      )}
      {view.phase === "problem" && (
        <div className="space-y-3">
          <p role="alert" className="text-sm text-destructive" data-testid="research-error">
            {view.problem.message}
            {view.problem.kind === "rate_limited" && view.problem.retryAfter
              ? ` Try again in about ${Math.ceil(view.problem.retryAfter / 60)} minute(s).`
              : ""}
          </p>
          {view.problem.kind !== "disabled" && view.problem.kind !== "not_found" && (
            <Button variant="outline" onClick={() => void start()} disabled={busy}>
              Generate learning guide
            </Button>
          )}
        </div>
      )}
    </SectionCard>
  );
}

function Intro({ busy, onStart }: { busy: boolean; onStart: () => void }) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">
        Turn this CVE into a structured learning guide built from public security research: vendor
        and CERT advisories, GitHub advisories, write-ups and more. The platform finds and reads
        the sources, and every statement in the guide is checked against them and cites where it
        came from. Where the sources do not say enough, the guide says so instead of guessing.
      </p>
      <p className="text-sm text-muted-foreground">
        For education and authorized testing only: reproduction guidance is limited to local,
        intentionally vulnerable or authorized lab environments. Nothing is run for you.
      </p>
      <Button onClick={onStart} disabled={busy}>
        {busy && <Loader2 aria-hidden className="size-4 animate-spin" />}
        Generate Learning Guide
      </Button>
    </div>
  );
}

function Progress({ status }: { status: ResearchStatus }) {
  const current = Math.max(0, STEPS.findIndex((s) => s.key === status.status));
  return (
    <div className="space-y-3" role="status" aria-live="polite" data-testid="research-progress">
      <ol className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
        {STEPS.map((step, index) => (
          <li
            key={step.key}
            aria-current={index === current ? "step" : undefined}
            data-state={index < current ? "done" : index === current ? "current" : "todo"}
            className={
              index < current
                ? "flex items-center gap-1 text-primary"
                : index === current
                  ? "flex items-center gap-1 font-semibold"
                  : "flex items-center gap-1 text-muted-foreground"
            }
          >
            {index < current ? (
              <Check aria-hidden className="size-4" />
            ) : index === current ? (
              <Loader2 aria-hidden className="size-4 animate-spin" />
            ) : (
              <span aria-hidden className="inline-block size-4 rounded-full border" />
            )}
            {step.label}
          </li>
        ))}
      </ol>
      <p className="text-sm text-muted-foreground">
        {status.stage}
        {status.stage_detail ? `: ${status.stage_detail}` : ""}. This usually takes a minute or two.
      </p>
    </div>
  );
}
