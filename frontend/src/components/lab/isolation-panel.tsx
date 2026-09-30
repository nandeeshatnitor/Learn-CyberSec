"use client";

import { Loader2, ShieldCheck, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { networkCheck } from "@/lib/sandbox-client";
import type { IsolationView } from "@/lib/sandbox-types";

/** Runs the platform's isolation proof again, on demand, from inside this lab's own network. */
export function IsolationPanel({ instanceId, enabled }: { instanceId: string; enabled: boolean }) {
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<IsolationView | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    const result = await networkCheck(instanceId);
    setBusy(false);
    if (result.ok) setReport(result.data);
    else setError(result.problem.message);
  }

  return (
    <div className="space-y-3 text-sm" data-testid="isolation-panel">
      <p className="text-muted-foreground">
        Your lab sits on its own private network with no route out. The platform proves that before the lab starts;
        run the same proof again whenever you like. It tries to reach the internet, the cloud metadata address, the
        host and other students&apos; labs from inside your lab&apos;s network.
      </p>
      <Button size="sm" onClick={() => void run()} disabled={busy || !enabled}>
        {busy && <Loader2 aria-hidden className="size-3.5 animate-spin" />} Run isolation check
      </Button>
      {error && (
        <p role="alert" className="text-destructive">
          {error}
        </p>
      )}
      {report && (
        <div className="space-y-2" data-testid="isolation-report">
          <p
            role="status"
            className={report.passed ? "flex items-center gap-2 font-medium" : "flex items-center gap-2 font-medium text-destructive"}
          >
            {report.passed ? <ShieldCheck aria-hidden className="size-4 text-primary" /> : <ShieldAlert aria-hidden className="size-4" />}
            {report.passed ? "Isolated: nothing was reachable." : "Something was reachable. This lab should not be used."}
          </p>
          <ul className="divide-y rounded-md border">
            {report.results.map((r) => (
              <li key={r.target} className="flex items-center justify-between gap-3 px-3 py-1.5">
                <span>{r.target}</span>
                <span className={r.blocked ? "text-xs text-muted-foreground" : "text-xs font-semibold text-destructive"}>
                  {r.blocked ? "Blocked" : "REACHABLE"}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
