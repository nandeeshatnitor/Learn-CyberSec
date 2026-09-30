"use client";

import "@xterm/xterm/css/xterm.css";
import { Loader2, RotateCcw } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { terminalTicket } from "@/lib/sandbox-client";

type State = "connecting" | "connected" | "closed";

const REASONS: Record<string, string> = {
  lab_ended: "The lab ended (it expired, was stopped or was reset).",
  idle: "Disconnected after a period of inactivity.",
  shell_exited: "The shell exited.",
  unauthorized: "The terminal session could not be authorised. Reconnect to try again.",
  busy: "This lab already has the maximum number of terminals open.",
  unavailable: "The terminal is not available right now.",
};

/** The WebSocket URL for a ticket: the gateway's own public address if it has one, else this site. */
export function socketUrl(ticket: { ticket: string; path: string; url: string | null }, loc: Location): string {
  const base = ticket.url ?? `${loc.protocol === "https:" ? "wss:" : "ws:"}//${loc.host}`;
  return `${base}${ticket.path}?ticket=${encodeURIComponent(ticket.ticket)}`;
}

/**
 * A browser terminal for a lab.
 *
 *   xterm.js  <--WebSocket-->  Terminal Gateway (the backend)  -->  the lab
 *
 * The browser never talks to the container runtime. It asks this site for a single-use ticket,
 * opens a WebSocket with it, and sends only what the student types and the window size.
 */
export function LabTerminal({ instanceId, active }: { instanceId: string; active: boolean }) {
  const host = useRef<HTMLDivElement | null>(null);
  const socket = useRef<WebSocket | null>(null);
  const [state, setState] = useState<State>("connecting");
  const [notice, setNotice] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const termRef = useRef<import("@xterm/xterm").Terminal | null>(null);

  useEffect(() => {
    if (!active || !host.current) return;
    let disposed = false;
    const cleanups: (() => void)[] = [];
    setState("connecting");
    setNotice(null);

    void (async () => {
      const [{ Terminal }, { FitAddon }] = await Promise.all([import("@xterm/xterm"), import("@xterm/addon-fit")]);
      if (disposed || !host.current) return;
      const term = new Terminal({
        cursorBlink: true,
        fontSize: 13,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
        theme: { background: "#0b1020", foreground: "#e5e7eb" },
        scrollback: 2000,
        rows: 24,
        cols: 80,
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      term.open(host.current);
      termRef.current = term;
      const refit = () => {
        try {
          fit.fit();
        } catch {
          /* the element is not laid out yet */
        }
      };
      refit();
      const observer = new ResizeObserver(refit);
      observer.observe(host.current);
      cleanups.push(() => observer.disconnect(), () => term.dispose());

      const ticket = await terminalTicket(instanceId);
      if (disposed) return;
      if (!ticket.ok) {
        setState("closed");
        setNotice(ticket.problem.message);
        return;
      }
      const ws = new WebSocket(socketUrl(ticket.data, window.location));
      ws.binaryType = "arraybuffer";
      socket.current = ws;
      cleanups.push(() => ws.close());
      const send = (message: object) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(message));
      };
      ws.onopen = () => {
        setState("connected");
        send({ type: "resize", cols: term.cols, rows: term.rows });
        term.focus();
      };
      ws.onmessage = (event: MessageEvent) => {
        if (typeof event.data === "string") {
          try {
            const message = JSON.parse(event.data) as { type?: string; reason?: string };
            if (message.type === "closed") {
              setNotice(REASONS[message.reason ?? ""] ?? "The terminal session ended.");
            }
          } catch {
            /* ignore malformed control frames */
          }
        } else {
          term.write(new Uint8Array(event.data as ArrayBuffer));
        }
      };
      ws.onclose = () => {
        if (!disposed) setState("closed");
      };
      ws.onerror = () => {
        if (!disposed) setNotice((n) => n ?? "The terminal connection failed.");
      };
      const data = term.onData((input) => send({ type: "input", data: input }));
      const resize = term.onResize(({ cols, rows }) => send({ type: "resize", cols, rows }));
      cleanups.push(() => data.dispose(), () => resize.dispose());
    })();

    return () => {
      disposed = true;
      cleanups.forEach((fn) => fn());
      socket.current = null;
      termRef.current = null;
    };
  }, [instanceId, active, attempt]);

  const reconnect = useCallback(() => setAttempt((n) => n + 1), []);

  return (
    <div className="space-y-2" data-testid="terminal">
      <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
        <span role="status" data-testid="terminal-state">
          {state === "connecting" && (
            <span className="inline-flex items-center gap-1">
              <Loader2 aria-hidden className="size-3 animate-spin" /> Connecting…
            </span>
          )}
          {state === "connected" && "Connected to your lab"}
          {state === "closed" && "Disconnected"}
        </span>
        {state === "closed" && active && (
          <Button size="sm" variant="outline" onClick={reconnect}>
            <RotateCcw aria-hidden className="size-3.5" /> Reconnect
          </Button>
        )}
      </div>
      {notice && (
        <p role="alert" className="rounded-md border border-warning/40 bg-warning/10 p-2 text-xs" data-testid="terminal-notice">
          {notice}
        </p>
      )}
      <div
        ref={host}
        className="h-[420px] overflow-hidden rounded-md border bg-[#0b1020] p-2"
        aria-label="Lab terminal"
        data-testid="terminal-screen"
      />
    </div>
  );
}
