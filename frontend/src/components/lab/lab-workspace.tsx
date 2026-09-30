"use client";

import { AlertTriangle, ExternalLink, Loader2, RotateCcw, Square, Timer } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

import { IsolationPanel } from "@/components/lab/isolation-panel";
import { ObjectivesPanel } from "@/components/lab/objectives-panel";
import { LabTerminal } from "@/components/lab/terminal";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import * as api from "@/lib/sandbox-client";
import type { InstanceView } from "@/lib/sandbox-types";
import type { ResearchProblem } from "@/lib/research-types";
import { cn } from "@/lib/utils";

type Tab = "terminal" | "app" | "isolation";

const POLL_MS = 10_000;

export function formatRemaining(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const rest = s % 60;
  const two = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${two(m)}:${two(rest)}` : `${two(m)}:${two(rest)}`;
}

const ENDED: Record<string, string> = {
  expired: "This lab’s time ran out and it was removed.",
  student: "You stopped this lab.",
  reset: "This lab was replaced by a fresh one.",
  failed: "This lab stopped unexpectedly.",
};

/**
 * The lab page: a disposable environment for hands-on practice. Terminal, the lab's web app and an
 * isolation report on one side; the objectives, checked against real behaviour, on the other.
 * Everything that matters (lease, state, progress) is on the server; this renders and asks.
 */
export function LabWorkspace({ instanceId, backHref }: { instanceId: string; backHref: string | null }) {
  const router = useRouter();
  const [instance, setInstance] = useState<InstanceView | null>(null);
  const [problem, setProblem] = useState<ResearchProblem | null>(null);
  const [tab, setTab] = useState<Tab>("terminal");
  const [busy, setBusy] = useState<"reset" | "stop" | "restart" | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [appKey, setAppKey] = useState(0);
  const [remaining, setRemaining] = useState(0);
  const deadline = useRef(0);
  const alive = useRef(true);

  const adopt = useCallback((next: InstanceView) => {
    setInstance(next);
    deadline.current = Date.now() + next.seconds_remaining * 1000;
    setRemaining(next.seconds_remaining);
  }, []);

  const refresh = useCallback(async () => {
    const result = await api.getInstance(instanceId);
    if (!alive.current) return;
    if (result.ok) adopt(result.data);
    else setProblem(result.problem);
  }, [instanceId, adopt]);

  useEffect(() => {
    alive.current = true;
    void (async () => {
      const result = await api.getInstance(instanceId);
      if (!alive.current) return;
      if (result.ok) adopt(result.data);
      else setProblem(result.problem);
    })();
    return () => {
      alive.current = false;
    };
  }, [instanceId, adopt]);

  const running = instance?.can_use === true;
  const live = instance !== null && ["starting", "running", "stopping"].includes(instance.status);
  useEffect(() => {
    if (!live) return;
    const poll = setInterval(() => void refresh(), POLL_MS);
    return () => clearInterval(poll);
  }, [live, refresh]);

  useEffect(() => {
    if (!running) return;
    const tick = setInterval(() => {
      const left = Math.max(0, Math.ceil((deadline.current - Date.now()) / 1000));
      setRemaining(left);
      if (left === 0) void refresh(); // the server decides: it expires the lab on access
    }, 1000);
    return () => clearInterval(tick);
  }, [running, refresh]);

  const withFrom = (id: string) => `/lab/${id}${backHref ? `?from=${encodeURIComponent(backHref)}` : ""}`;

  async function reset() {
    if (!instance) return;
    setBusy("reset");
    setError(null);
    setConfirmReset(false);
    const result = await api.resetInstance(instance.id);
    if (!alive.current) return;
    setBusy(null);
    if (result.ok) router.replace(withFrom(result.data.id));
    else {
      setError(result.problem.message);
      void refresh();
    }
  }

  async function stop() {
    if (!instance) return;
    setBusy("stop");
    setError(null);
    const result = await api.stopInstance(instance.id);
    if (!alive.current) return;
    setBusy(null);
    if (result.ok) adopt(result.data);
    else setError(result.problem.message);
  }

  async function startAgain() {
    if (!instance) return;
    setBusy("restart");
    setError(null);
    const result = await api.startLab(instance.lab.id, instance.session_id);
    if (!alive.current) return;
    setBusy(null);
    if (result.ok) router.replace(withFrom(result.data.id));
    else setError(result.problem.message);
  }

  if (problem) {
    return (
      <Card>
        <CardContent className="space-y-3 p-6 text-sm">
          <p role="alert" className="text-destructive" data-testid="lab-error">
            {problem.kind === "not_found" ? "This lab could not be found. It may belong to someone else, or it was removed." : problem.message}
          </p>
          <Button asChild variant="outline">
            <Link href={backHref ?? "/labs"}>{backHref ? "Back to your lesson" : "See the labs"}</Link>
          </Button>
        </CardContent>
      </Card>
    );
  }
  if (!instance) {
    return (
      <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 aria-hidden className="size-4 animate-spin" /> Loading your lab…
      </p>
    );
  }

  const ended = !running && instance.status !== "starting";
  const almostOut = running && remaining <= 300;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight">{instance.lab.title}</h1>
            <Badge
              variant={instance.status === "running" ? "default" : instance.status === "failed" ? "destructive" : "muted"}
              data-testid="lab-status"
            >
              {instance.status}
            </Badge>
          </div>
          <p className="max-w-3xl text-sm text-muted-foreground">{instance.lab.summary}</p>
        </div>
        {running && (
          <div className="flex flex-wrap items-center gap-2">
            <span
              role="timer"
              aria-label="Time left in this lab"
              data-testid="lab-timer"
              className={cn(
                "inline-flex items-center gap-1 rounded-md border px-2 py-1 font-mono text-sm",
                almostOut && "border-warning/50 bg-warning/10 text-warning",
              )}
            >
              <Timer aria-hidden className="size-4" /> {formatRemaining(remaining)}
            </span>
            {confirmReset ? (
              <span className="flex flex-wrap items-center gap-2 rounded-md border border-warning/40 bg-warning/10 px-2 py-1 text-xs">
                Reset deletes everything you changed in this lab.
                <Button size="sm" onClick={() => void reset()} disabled={busy !== null}>
                  Yes, reset
                </Button>
                <Button size="sm" variant="outline" onClick={() => setConfirmReset(false)}>
                  Cancel
                </Button>
              </span>
            ) : (
              <Button size="sm" variant="outline" onClick={() => setConfirmReset(true)} disabled={busy !== null}>
                {busy === "reset" ? <Loader2 aria-hidden className="size-3.5 animate-spin" /> : <RotateCcw aria-hidden className="size-3.5" />}
                Reset lab
              </Button>
            )}
            <Button size="sm" variant="outline" onClick={() => void stop()} disabled={busy !== null}>
              {busy === "stop" ? <Loader2 aria-hidden className="size-3.5 animate-spin" /> : <Square aria-hidden className="size-3.5" />}
              Stop lab
            </Button>
          </div>
        )}
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive" data-testid="lab-error">
          {error}
        </p>
      )}
      {almostOut && (
        <p role="status" className="flex items-center gap-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-sm">
          <AlertTriangle aria-hidden className="size-4 text-warning" /> Less than five minutes left. When the time runs out the lab is
          deleted; your verified objectives are kept.
        </p>
      )}

      {instance.status === "starting" && (
        <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 aria-hidden className="size-4 animate-spin" /> Your lab is starting…
        </p>
      )}

      {ended && (
        <Card data-testid="lab-ended">
          <CardContent className="space-y-3 p-6 text-sm">
            <p className="font-medium">
              {instance.failure_message ?? ENDED[instance.stop_reason ?? ""] ?? "This lab is no longer running."}
            </p>
            <p className="text-muted-foreground">
              Everything inside it has been deleted. The objectives you verified are kept
              {instance.objectives.some((o) => o.verified) ? ` (${instance.objectives.filter((o) => o.verified).length} of ${instance.objectives.length})` : ""}.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => void startAgain()} disabled={busy !== null}>
                {busy === "restart" && <Loader2 aria-hidden className="size-4 animate-spin" />} Start a fresh lab
              </Button>
              <Button asChild variant="outline">
                <Link href={backHref ?? "/labs"}>{backHref ? "Back to your lesson" : "See the labs"}</Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-6 lg:grid-cols-[340px_minmax(0,1fr)]">
        <aside className="space-y-4" aria-label="Objectives and instructions">
          <ObjectivesPanel instance={instance} onInstance={adopt} />
          <Card>
            <CardHeader>
              <CardTitle>How to work in this lab</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <ol className="list-decimal space-y-2 pl-5" data-testid="lab-instructions">
                {instance.lab.instructions.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
              <dl className="grid grid-cols-2 gap-2 border-t pt-3 text-xs text-muted-foreground">
                <dt>CPU / memory</dt>
                <dd>
                  {instance.lab.resources.cpus} CPU · {instance.lab.resources.memory_mb} MB
                </dd>
                <dt>Processes</dt>
                <dd>{instance.lab.resources.processes} at most</dd>
                <dt>Lasts</dt>
                <dd>{instance.lab.resources.timeout_minutes} minutes</dd>
                <dt>Network</dt>
                <dd>none</dd>
              </dl>
              <p className="text-xs text-muted-foreground">{instance.lab.network}</p>
            </CardContent>
          </Card>
          <p className="rounded-md border border-warning/40 bg-warning/10 p-3 text-xs" data-testid="lab-safety">
            {instance.safety_notice}
          </p>
        </aside>

        <main className="min-w-0">
          <Card>
            <CardHeader className="pb-2">
              <div role="tablist" aria-label="Lab tools" className="flex flex-wrap gap-1">
                {(
                  [
                    ["terminal", "Terminal"],
                    ["app", "Lab app"],
                    ["isolation", "Isolation"],
                  ] as [Tab, string][]
                ).map(([id, label]) => (
                  <button
                    key={id}
                    role="tab"
                    type="button"
                    aria-selected={tab === id}
                    aria-controls={`panel-${id}`}
                    id={`tab-${id}`}
                    onClick={() => setTab(id)}
                    className={cn(
                      "rounded-md px-3 py-1.5 text-sm font-medium",
                      tab === id ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:bg-accent/60",
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </CardHeader>
            <CardContent>
              {/* The terminal stays mounted while another tab is shown, so the session survives. */}
              <div role="tabpanel" id="panel-terminal" aria-labelledby="tab-terminal" hidden={tab !== "terminal"}>
                <LabTerminal key={instance.id} instanceId={instance.id} active={running} />
              </div>
              <div role="tabpanel" id="panel-app" aria-labelledby="tab-app" hidden={tab !== "app"}>
                {tab === "app" && instance.app_path ? (
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
                      <span>The lab’s web app, served through the platform. It is untrusted and runs in a sandboxed frame.</span>
                      <span className="flex gap-2">
                        <Button size="sm" variant="outline" onClick={() => setAppKey((k) => k + 1)}>
                          <RotateCcw aria-hidden className="size-3.5" /> Reload
                        </Button>
                        <Button size="sm" variant="outline" asChild>
                          <a href={instance.app_path} target="_blank" rel="noopener noreferrer">
                            <ExternalLink aria-hidden className="size-3.5" /> Open in a new tab
                          </a>
                        </Button>
                      </span>
                    </div>
                    <iframe
                      key={appKey}
                      src={instance.app_path}
                      title="Lab web app"
                      sandbox="allow-forms allow-scripts"
                      referrerPolicy="no-referrer"
                      className="h-[420px] w-full rounded-md border bg-white"
                      data-testid="lab-app-frame"
                    />
                  </div>
                ) : (
                  tab === "app" && <p className="text-sm text-muted-foreground">The lab’s web app is available while the lab is running.</p>
                )}
              </div>
              <div role="tabpanel" id="panel-isolation" aria-labelledby="tab-isolation" hidden={tab !== "isolation"}>
                <IsolationPanel instanceId={instance.id} enabled={running} />
              </div>
            </CardContent>
          </Card>
          {backHref && (
            <p className="mt-3 text-sm">
              <Link href={backHref} className="text-primary underline-offset-4 hover:underline">
                ← Back to your lesson
              </Link>
            </p>
          )}
        </main>
      </div>
    </div>
  );
}
