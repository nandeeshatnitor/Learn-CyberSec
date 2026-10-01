"use client";

import { Loader2, LogOut } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import * as api from "@/lib/admin-client";
import type { Reviewer } from "@/lib/admin-types";
import type { ResearchProblem } from "@/lib/research-types";

type Phase =
  | { kind: "checking" }
  | { kind: "signed_out"; message?: string }
  | { kind: "disabled"; message: string }
  | { kind: "error"; message: string }
  | { kind: "ready"; reviewer: Reviewer };

/**
 * Everything under /admin needs a signed-in reviewer. The token is pasted once, checked by the
 * server and kept in an HttpOnly cookie: this component only ever learns who the reviewer is.
 */
export function AdminGate({
  children,
}: {
  children: (reviewer: Reviewer, signOut: () => void) => ReactNode;
}) {
  const [phase, setPhase] = useState<Phase>({ kind: "checking" });
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);

  const fromProblem = (p: ResearchProblem): Phase =>
    p.kind === "unauthorized"
      ? { kind: "signed_out" }
      : p.kind === "disabled"
        ? { kind: "disabled", message: p.message }
        : { kind: "error", message: p.message };

  useEffect(() => {
    let alive = true;
    void (async () => {
      const result = await api.whoami();
      if (!alive) return;
      setPhase(result.ok ? { kind: "ready", reviewer: result.data } : fromProblem(result.problem));
    })();
    return () => {
      alive = false;
    };
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    const result = await api.signIn(token.trim());
    setBusy(false);
    setToken("");
    if (result.ok) setPhase({ kind: "ready", reviewer: result.data });
    else
      setPhase(
        result.problem.kind === "unauthorized"
          ? { kind: "signed_out", message: "That token was not accepted." }
          : result.problem.kind === "rate_limited"
            ? {
                kind: "signed_out",
                message: "Too many attempts. Please wait a minute.",
              }
            : fromProblem(result.problem),
      );
  }

  // Stable, so pages can use it as an effect dependency without refetching on every render.
  const signOut = useCallback(() => {
    void (async () => {
      await api.signOut();
      setPhase({ kind: "signed_out" });
    })();
  }, []);

  if (phase.kind === "checking") {
    return (
      <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 aria-hidden className="size-4 animate-spin" /> Checking your session…
      </p>
    );
  }
  if (phase.kind === "disabled" || phase.kind === "error") {
    return (
      <p role="status" className="text-sm text-muted-foreground" data-testid="admin-unavailable">
        {phase.message}
      </p>
    );
  }
  if (phase.kind === "signed_out") {
    return (
      <Card className="max-w-md" data-testid="admin-sign-in">
        <CardHeader>
          <CardTitle className="text-lg">Reviewer sign-in</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={(e) => void submit(e)} className="space-y-3">
            <label htmlFor="admin-token" className="text-sm font-medium">
              Reviewer token
            </label>
            <Input
              id="admin-token"
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              maxLength={128}
              aria-describedby="admin-token-help"
            />
            <p id="admin-token-help" className="text-xs text-muted-foreground">
              Issued by an administrator (<code>scripts/admin_token.py</code>). It is kept in a
              cookie that page scripts cannot read.
            </p>
            {phase.message && (
              <p role="alert" className="text-sm text-destructive">
                {phase.message}
              </p>
            )}
            <Button type="submit" disabled={busy || token.trim().length < 20}>
              {busy && <Loader2 aria-hidden className="size-4 animate-spin" />} Sign in
            </Button>
          </form>
        </CardContent>
      </Card>
    );
  }
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end gap-3 text-sm text-muted-foreground">
        <span data-testid="reviewer-name">
          Signed in as <strong className="text-foreground">{phase.reviewer.name}</strong>
        </span>
        <Button variant="outline" size="sm" onClick={signOut}>
          <LogOut aria-hidden className="size-3.5" /> Sign out
        </Button>
      </div>
      {children(phase.reviewer, signOut)}
    </div>
  );
}
